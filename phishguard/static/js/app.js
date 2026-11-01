// PhishGuard — shared behaviour for every page.
// No inline scripts are used (strict CSP); user-controlled text is only ever
// written with textContent, never innerHTML.
"use strict";

(function () {
  // Mobile navigation toggle
  const toggle = document.querySelector(".nav-toggle");
  const nav = document.getElementById("site-nav");
  if (toggle && nav) {
    toggle.addEventListener("click", () => {
      const open = nav.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", String(open));
    });
  }

  // Dismissible flash messages
  document.querySelectorAll("[data-dismiss]").forEach((button) => {
    button.addEventListener("click", () => {
      const flash = button.closest(".flash");
      if (flash) flash.remove();
    });
  });

  // Confirmation before destructive form submissions
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.getAttribute("data-confirm") || "Are you sure?")) {
        event.preventDefault();
      }
    });
  });

  // Horizontal bars and meters: width comes from a data attribute because the
  // CSP forbids inline style attributes.
  const clamp = (value) => Math.max(0, Math.min(100, Number.parseFloat(value) || 0));
  requestAnimationFrame(() => {
    document.querySelectorAll("[data-bar]").forEach((el) => {
      const pct = clamp(el.getAttribute("data-bar"));
      const fill = el.classList.contains("meter") ? el.querySelector(".meter__fill") : el;
      if (fill) fill.style.width = pct + "%";
    });
  });

  window.PhishGuard = window.PhishGuard || {};
  window.PhishGuard.clamp = clamp;
  window.PhishGuard.csrfToken = () => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  };
})();
