// PhishGuard — history filters: apply the verdict filter as soon as it changes.
"use strict";

(function () {
  const form = document.querySelector("[data-filter-form]");
  if (!form) return;
  const verdict = form.querySelector("#verdict");
  if (verdict) {
    verdict.addEventListener("change", () => form.requestSubmit ? form.requestSubmit() : form.submit());
  }
})();
