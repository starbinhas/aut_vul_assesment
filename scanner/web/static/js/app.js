// Comportamentos pequenos da interface. Sem dependências além do HTMX.
(function () {
  "use strict";

  // Botões "Copiar" (registro DNS, comandos de correção).
  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy]");
    if (!button) return;
    var source = document.getElementById(button.getAttribute("data-copy"));
    if (!source || !navigator.clipboard) return;
    navigator.clipboard.writeText(source.textContent.trim()).then(function () {
      var label = button.textContent;
      button.textContent = "Copiado";
      setTimeout(function () { button.textContent = label; }, 1500);
    });
  });

  // Abre a falha indicada no endereço (#item-xxxx), por exemplo depois de uma revisão.
  function openFromHash() {
    if (!location.hash) return;
    var el = document.getElementById(location.hash.slice(1));
    if (el && el.tagName === "DETAILS") { el.open = true; el.scrollIntoView({ block: "start" }); }
  }
  window.addEventListener("hashchange", openFromHash);
  document.addEventListener("DOMContentLoaded", openFromHash);
})();
