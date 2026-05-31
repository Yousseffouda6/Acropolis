// Acropolis Notes - small progressive enhancements (no framework).
(function () {
  "use strict";

  // --- Toasts: auto-dismiss + manual close --------------------------------
  function dismiss(toast) {
    toast.classList.add("is-leaving");
    setTimeout(function () { toast.remove(); }, 260);
  }
  document.querySelectorAll(".toast").forEach(function (toast) {
    var close = toast.querySelector(".toast__close");
    if (close) close.addEventListener("click", function () { dismiss(toast); });
    setTimeout(function () { dismiss(toast); }, 4200);
  });

  // --- Live search filter on the dashboard --------------------------------
  var search = document.getElementById("note-search");
  var grid = document.getElementById("note-grid");
  if (search && grid) {
    var cards = Array.prototype.slice.call(grid.querySelectorAll(".note-card"));
    var empty = document.getElementById("search-empty");
    var term = document.getElementById("search-empty-term");
    search.addEventListener("input", function () {
      var q = search.value.trim().toLowerCase();
      var shown = 0;
      cards.forEach(function (card) {
        var hit = !q || (card.getAttribute("data-search") || "").indexOf(q) !== -1;
        card.hidden = !hit;
        if (hit) shown++;
      });
      if (empty) {
        empty.hidden = !(q && shown === 0);
        if (term) term.textContent = '"' + search.value.trim() + '"';
      }
    });
  }

  // --- Confirm before destructive form submits ----------------------------
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });

  // --- Copy-to-clipboard buttons ------------------------------------------
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = document.querySelector(btn.getAttribute("data-copy"));
      if (!target) return;
      var text = target.textContent.trim();
      var done = function () {
        var label = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = label; }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        done();
      }
    });
  });
})();
