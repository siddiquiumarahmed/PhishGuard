// PhishGuard — scan form: sample buttons, light client-side checks, loading state.
// The server performs the authoritative validation; these checks only give
// faster feedback for the most common mistakes.
"use strict";

(function () {
  const form = document.querySelector("[data-scan-form]");
  if (!form) return;

  const input = form.querySelector("#url-input");
  const errorEl = form.querySelector("[data-error]");
  const submit = form.querySelector("[data-submit]");
  const submitLabel = form.querySelector("[data-submit-label]");
  const maxLength = Number.parseInt(input.getAttribute("maxlength"), 10) - 64;

  function showError(message) {
    errorEl.textContent = message;
    errorEl.hidden = !message;
    if (message) {
      input.setAttribute("aria-invalid", "true");
      input.setAttribute("aria-describedby", "url-help url-error");
    } else {
      input.removeAttribute("aria-invalid");
      input.setAttribute("aria-describedby", "url-help");
    }
  }

  function quickCheck(value) {
    const trimmed = value.trim();
    if (!trimmed) return "Enter a URL to scan.";
    if (trimmed.length > maxLength) return `The URL is longer than the ${maxLength}-character limit.`;
    if (/\s/.test(trimmed)) {
      return "The URL contains spaces. Real addresses encode spaces as %20; check that you copied the whole link correctly.";
    }
    const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(trimmed);
    if (!scheme || scheme[1].includes(".") || /^\d/.test(trimmed.slice(scheme[0].length))) {
      return "Include the scheme at the start of the address, for example https://example.com.";
    }
    if (!["http", "https"].includes(scheme[1].toLowerCase())) {
      return "Only http:// and https:// web addresses can be scanned.";
    }
    return "";
  }

  document.querySelectorAll("[data-example]").forEach((button) => {
    button.addEventListener("click", () => {
      input.value = button.getAttribute("data-example") || "";
      showError("");
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
    });
  });

  input.addEventListener("input", () => {
    if (!errorEl.hidden) showError("");
  });

  form.addEventListener("submit", (event) => {
    const problem = quickCheck(input.value);
    if (problem) {
      event.preventDefault();
      showError(problem);
      input.focus();
      return;
    }
    submit.disabled = true;
    submit.setAttribute("aria-busy", "true");
    submitLabel.textContent = "Analysing…";
  });

  // Restore the button if the page is shown again from the back/forward cache.
  window.addEventListener("pageshow", () => {
    submit.disabled = false;
    submit.removeAttribute("aria-busy");
    submitLabel.textContent = "Scan link";
  });
})();
