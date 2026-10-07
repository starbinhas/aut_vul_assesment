from scanner.common.masking import MASK, mask_headers, mask_obj, mask_text


def test_masks_sensitive_headers() -> None:
    out = mask_headers({"Cookie": "sid=abc", "Authorization": "Bearer xyz", "Accept": "text/html"})
    assert out == {"Cookie": MASK, "Authorization": MASK, "Accept": "text/html"}


def test_masks_tokens_in_text() -> None:
    text = "GET /api?token=s3cr3t&page=2 password=hunter2 Bearer abc.def eyJhbGciOi.eyJzdWIi.sig"
    out = mask_text(text)
    assert "s3cr3t" not in out and "hunter2" not in out and "abc.def" not in out
    assert "eyJhbGciOi" not in out
    assert "page=2" in out


def test_masks_pii() -> None:
    out = mask_text("contato: maria@exemplo.com.br cpf 123.456.789-09 cartão 4111 1111 1111 1111")
    assert "maria@" not in out and "123.456" not in out and "4111" not in out


def test_mask_obj_recurses_and_masks_sensitive_keys() -> None:
    out = mask_obj(
        {"credential": {"name": "Authorization", "value": "Bearer x"}, "n": [{"api_key": "k"}]}
    )
    assert out == {"credential": MASK, "n": [{"api_key": MASK}]}
