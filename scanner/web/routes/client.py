"""Área do cliente (o admin também usa estas telas, vendo todas as organizações)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from scanner.common.db import Organization, Report, Scan, ScanStatus, StageProgress, Target
from scanner.common.models import Severity, Status
from scanner.report.models import Report as ReportModel
from scanner.report.models import ReportItem
from scanner.report.names import display_title
from scanner.web import labels, verification
from scanner.web.deps import current_viewer, get_db, render
from scanner.web.security import csrf_protect
from scanner.web.services import (
    Comparison,
    ScanNotAllowedError,
    active_scan,
    audit,
    compare,
    item_id,
    load_report,
    previous_done_scan,
    profiles_for,
    reviews_since_report,
    site_map,
    start_scan,
    trend_paths,
)
from scanner.web.tenancy import Viewer, get_report, get_scan, get_target, not_found, scans_query
from scanner.web.tenancy import targets_query as tq

router = APIRouter(dependencies=[Depends(csrf_protect)])

RECURRENCE = {"manual": "Só quando eu pedir", "weekly": "Toda semana", "monthly": "Todo mês"}
OPEN = (Status.CONFIRMED, Status.LIKELY, Status.UNCONFIRMED)
SCAN_ERRORS = {
    "nao-verificado": "Comprove que o domínio é seu antes de iniciar um scan.",
    "em-andamento": "Já existe um scan em andamento para este site.",
    "perfil-nao-permitido": "Esse nível de scan não está liberado para este site.",
}


@dataclass
class SiteSummary:
    target: Target
    org: str | None
    last_scan: Scan | None
    report: ReportModel | None
    report_scan: Scan | None
    comparison: Comparison | None


def _site_summary(db: Session, target: Target) -> SiteSummary:
    last = db.scalars(scans_for(target).limit(1)).first()
    done = db.scalars(
        scans_for(target)
        .join(Report, Report.scan_id == Scan.scan_id)
        .where(Scan.status == ScanStatus.DONE)
        .limit(1)
    ).first()
    report = load_report(db.get(Report, done.scan_id)) if done else None
    comparison = None
    if done and report:
        prev = previous_done_scan(db, done)
        comparison = compare(
            report,
            load_report(db.get(Report, prev.scan_id)) if prev else None,
            done.pages_crawled,
            prev.pages_crawled if prev else None,
        )
    org = db.get(Organization, target.org_id)
    return SiteSummary(target, org.name if org else None, last, report, done, comparison)


def scans_for(target: Target):  # type: ignore[no-untyped-def]
    return select(Scan).where(Scan.target_id == target.target_id).order_by(Scan.created_at.desc())


# --- painel -----------------------------------------------------------------------------


@router.get("/painel")
def dashboard(
    request: Request, viewer: Viewer = Depends(current_viewer), db: Session = Depends(get_db)
) -> Response:
    sites = [_site_summary(db, t) for t in db.scalars(tq(viewer))]
    fix_now: list[tuple[SiteSummary, ReportItem]] = []
    new_items: list[tuple[SiteSummary, ReportItem]] = []
    gone_items: list[tuple[SiteSummary, ReportItem]] = []
    not_retested: list[tuple[SiteSummary, ReportItem]] = []
    totals = dict.fromkeys(("new", "gone", "open"), 0)
    for s in sites:
        if s.report:
            open_items = [i for i in s.report.items if i.status in OPEN]
            totals["open"] += len(open_items)
            fix_now += [
                (s, i)
                for i in open_items
                if i.status in (Status.CONFIRMED, Status.LIKELY)
                and i.severity.rank >= Severity.MEDIUM.rank
            ]
        if s.comparison:
            totals["new"] += len(s.comparison.new)
            totals["gone"] += len(s.comparison.gone)
            new_items += [(s, i) for i in s.comparison.new]
            gone_items += [(s, i) for i in s.comparison.gone]
            not_retested += [(s, i) for i in s.comparison.not_retested]
    fix_now.sort(key=lambda p: (-p[1].severity.rank, p[1].status != Status.CONFIRMED))
    recent = db.scalars(scans_query(viewer).limit(8)).all()
    domains = {s.target.target_id: s.target.domain for s in sites}
    return render(
        request,
        "client/dashboard.html",
        viewer,
        db,
        sites=sites,
        fix_now=fix_now[:6],
        new_items=sorted(new_items, key=lambda p: -p[1].severity.rank),
        gone_items=sorted(gone_items, key=lambda p: -p[1].severity.rank),
        not_retested=sorted(not_retested, key=lambda p: -p[1].severity.rank),
        totals=totals,
        recent=recent,
        domains=domains,
        item_id=item_id,
    )


# --- sites ------------------------------------------------------------------------------


@router.get("/sites")
def sites_list(
    request: Request, viewer: Viewer = Depends(current_viewer), db: Session = Depends(get_db)
) -> Response:
    sites = [_site_summary(db, t) for t in db.scalars(tq(viewer))]
    return render(request, "client/sites.html", viewer, db, sites=sites)


def _orgs(db: Session) -> list[Organization]:
    return list(db.scalars(select(Organization).order_by(Organization.name)))


@router.get("/sites/novo")
def site_new(
    request: Request, viewer: Viewer = Depends(current_viewer), db: Session = Depends(get_db)
) -> Response:
    return render(
        request,
        "client/site_new.html",
        viewer,
        db,
        error=None,
        value="",
        orgs=_orgs(db) if viewer.is_admin else [],
    )


@router.post("/sites")
def site_create(
    request: Request,
    site: str = Form(...),
    org_id: str | None = Form(None),
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    owner = org_id if viewer.is_admin else viewer.org_id
    error = None
    try:
        domain, base_url = verification.normalize_site(site)
    except verification.InvalidSiteError as exc:
        error = str(exc)
    if not error and (owner is None or db.get(Organization, owner) is None):
        error = "Escolha a organização dona do site."
    if not error:
        exists = db.scalars(
            select(Target).where(Target.org_id == owner, Target.domain == domain)
        ).first()
        if exists:
            return RedirectResponse(f"/sites/{exists.target_id}", 303)
        target = Target(
            target_id=f"site-{verification.new_token()[:12]}",
            org_id=owner,
            domain=domain,
            base_url=base_url,
            verification_token=verification.new_token(),
            created_by=viewer.user_id,
        )
        db.add(target)
        try:
            db.flush()
        except IntegrityError:
            error = "Esse site já está cadastrado."
        else:
            audit(
                db,
                viewer,
                "site.create",
                org_id=owner,
                object_type="site",
                object_id=target.target_id,
                domain=domain,
            )
            return RedirectResponse(f"/sites/{target.target_id}", 303)
    return render(
        request,
        "client/site_new.html",
        viewer,
        db,
        status_code=400,
        error=error,
        value=site,
        orgs=_orgs(db) if viewer.is_admin else [],
    )


@router.get("/sites/{target_id}")
def site_detail(
    request: Request,
    target_id: str,
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    target = get_target(db, viewer, target_id)
    scans = db.scalars(scans_for(target).limit(30)).all()
    reports = {
        r.scan_id: load_report(r)
        for r in db.scalars(select(Report).where(Report.scan_id.in_([s.scan_id for s in scans])))
    }
    # Falhas abertas a cada scan concluído, do mais antigo ao mais recente.
    history = [
        (s, sum(1 for i in rep.items if i.status in OPEN))
        for s in reversed(scans)
        if s.status == ScanStatus.DONE and (rep := reports.get(s.scan_id))
    ]
    line, area = trend_paths([n for _, n in history])
    return render(
        request,
        "client/site_detail.html",
        viewer,
        db,
        s=_site_summary(db, target),
        scans=scans,
        reports=reports,
        trend={"line": line, "area": area, "history": history},
        running=active_scan(db, target.target_id),
        record_name=verification.record_name(target.domain),
        record_value=verification.record_value(target.verification_token),
        recurrence=RECURRENCE,
        profiles=profiles_for(viewer, target, request.app.state.settings.lab_hosts),
        # Só códigos conhecidos: texto livre na URL viraria injeção de conteúdo.
        error=SCAN_ERRORS.get(request.query_params.get("erro", "")),
    )


@router.post("/sites/{target_id}/verificar")
def site_verify(
    request: Request,
    target_id: str,
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    target = get_target(db, viewer, target_id)
    if target.verified_at is None:
        problem = verification.check_txt(target.domain, target.verification_token)
        target.last_check_at = datetime.now(UTC)
        target.last_check_error = problem
        if problem is None:
            target.verified_at = target.last_check_at
            audit(
                db,
                viewer,
                "site.verified",
                org_id=target.org_id,
                object_type="site",
                object_id=target.target_id,
                domain=target.domain,
            )
    return RedirectResponse(f"/sites/{target.target_id}", 303)


@router.post("/sites/{target_id}/scans")
def site_scan(
    request: Request,
    target_id: str,
    profile: str = Form("safe"),
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    target = get_target(db, viewer, target_id)
    lab_hosts = request.app.state.settings.lab_hosts
    try:
        scan = start_scan(db, viewer, target, request.app.state.publish, lab_hosts, profile)
    except ScanNotAllowedError as exc:
        return RedirectResponse(f"/sites/{target.target_id}?erro={exc.code}", 303)
    return RedirectResponse(f"/scans/{scan.scan_id}", 303)


@router.post("/sites/{target_id}/recorrencia")
def site_recurrence(
    request: Request,
    target_id: str,
    recurrence: str = Form(...),
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    target = get_target(db, viewer, target_id)
    if recurrence not in RECURRENCE:
        raise not_found()
    target.recurrence = recurrence
    audit(
        db,
        viewer,
        "site.recurrence",
        org_id=target.org_id,
        object_type="site",
        object_id=target.target_id,
        recurrence=recurrence,
    )
    return RedirectResponse(f"/sites/{target.target_id}", 303)


# --- scans ------------------------------------------------------------------------------


def _filter(items: list[ReportItem], sev: list[str], st: list[str], q: str) -> list[ReportItem]:
    q = q.strip().lower()
    return [
        i
        for i in items
        if (not sev or i.severity.value in sev)
        and (not st or i.status.value in st)
        and (
            not q
            or q in i.finding.title.lower()
            or q in display_title(i.finding.title).lower()
            or any(q in loc.url.lower() for loc in i.locations)
        )
    ]


@router.get("/scans/{scan_id}")
def scan_detail(
    request: Request,
    scan_id: str,
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    scan, target = get_scan(db, viewer, scan_id)
    report_row = db.get(Report, scan_id)
    report = load_report(report_row)
    sev = request.query_params.getlist("sev")
    st = request.query_params.getlist("st")
    q = request.query_params.get("q", "")
    comparison = None
    if report:
        prev = previous_done_scan(db, scan)
        comparison = compare(
            report,
            load_report(db.get(Report, prev.scan_id)) if prev else None,
            scan.pages_crawled,
            prev.pages_crawled if prev else None,
        )
    tools_done = list(
        db.scalars(select(StageProgress.tool).where(StageProgress.scan_id == scan_id))
    )
    return render(
        request,
        "client/scan.html",
        viewer,
        db,
        scan=scan,
        target=target,
        report=report,
        coverage_partial=(
            scan.pages_crawled is not None
            and scan.pages_crawled < request.app.state.settings.coverage_min_pages
        ),
        items=_filter(report.items, sev, st, q) if report else [],
        comparison=comparison,
        sitemap=site_map(report) if report and report.items else None,
        uniform_status=(
            report.items[0].status
            if report and report.items and len({i.status for i in report.items}) == 1
            else None
        ),
        new_keys={i.group_key for i in comparison.new} if comparison else set(),
        filters={"sev": sev, "st": st, "q": q},
        # Só filtros que mudam algo: severidade/situação presente no relatório (ou já marcada).
        severities=[
            s
            for s in Severity
            if s.value in sev or (report and report.summary.by_severity.get(s.value))
        ],
        statuses=[
            s
            for s in (Status.CONFIRMED, Status.LIKELY, Status.UNCONFIRMED)
            if s.value in st or (report and report.summary.by_status.get(s.value))
        ],
        steps=labels.STEPS,
        item_id=item_id,
        pending_reviews=reviews_since_report(db, scan_id, report_row) if viewer.is_admin else 0,
        tools_done=tools_done,
    )


@router.get("/scans/{scan_id}/andamento")
def scan_progress(
    request: Request,
    scan_id: str,
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    scan, _ = get_scan(db, viewer, scan_id)
    if scan.status == ScanStatus.DONE and db.get(Report, scan_id) is not None:
        return Response(status_code=204, headers={"HX-Refresh": "true"})
    return render(request, "partials/progress.html", viewer, scan=scan, steps=labels.STEPS)


@router.post("/scans/{scan_id}/parar")
def scan_stop_partial(
    scan_id: str,
    viewer: Viewer = Depends(current_viewer),
    db: Session = Depends(get_db),
) -> Response:
    """Operador para a espera (alvo instável) e pede o relatório parcial agora.

    Só marca a hora; o worker lê no laço de espera e entrega o parcial. Idempotente.
    """
    scan, target = get_scan(db, viewer, scan_id)
    if scan.stop_requested_at is None:
        scan.stop_requested_at = datetime.now(UTC)
        audit(
            db,
            viewer,
            "scan.stop_partial",
            org_id=target.org_id if target else None,
            object_type="scan",
            object_id=scan.scan_id,
        )
    return RedirectResponse(f"/scans/{scan.scan_id}", 303)


def _report_or_404(db: Session, viewer: Viewer, scan_id: str) -> Report:
    _, report = get_report(db, viewer, scan_id)
    if report is None:
        raise not_found()
    return report


@router.get("/scans/{scan_id}/relatorio.pdf")
def report_pdf(
    scan_id: str, viewer: Viewer = Depends(current_viewer), db: Session = Depends(get_db)
) -> Response:
    report = _report_or_404(db, viewer, scan_id)
    return Response(
        report.pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="relatorio-{scan_id}.pdf"'},
    )


@router.get("/scans/{scan_id}/relatorio.html")
def report_html(
    scan_id: str, viewer: Viewer = Depends(current_viewer), db: Session = Depends(get_db)
) -> Response:
    report = _report_or_404(db, viewer, scan_id)
    return Response(report.html, media_type="text/html; charset=utf-8")
