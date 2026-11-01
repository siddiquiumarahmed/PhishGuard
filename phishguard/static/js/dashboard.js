// PhishGuard — dashboard: size the daily activity columns from data attributes.
// (Inline style attributes are blocked by the Content-Security-Policy.)
"use strict";

(function () {
  const clamp = (window.PhishGuard && window.PhishGuard.clamp) ||
    ((v) => Math.max(0, Math.min(100, Number.parseFloat(v) || 0)));
  requestAnimationFrame(() => {
    document.querySelectorAll("[data-bar-height]").forEach((el) => {
      el.style.height = clamp(el.getAttribute("data-bar-height")) + "%";
    });
  });
})();
