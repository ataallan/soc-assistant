(function () {
  document.querySelectorAll("input[data-autofill-guard]").forEach(function (input) {
    input.addEventListener("focus", function () {
      input.removeAttribute("readonly");
    });
  });

  document.querySelectorAll("[data-toggle-password]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-toggle-password"));
      if (!input) return;
      var showing = input.getAttribute("type") === "text";
      input.setAttribute("type", showing ? "password" : "text");
      btn.textContent = showing ? "Show" : "Hide";
      btn.setAttribute("aria-pressed", showing ? "false" : "true");
      var showLabel = btn.getAttribute("data-show-label") || "Show password";
      var hideLabel = btn.getAttribute("data-hide-label") || "Hide password";
      btn.setAttribute("aria-label", showing ? showLabel : hideLabel);
    });
  });

  var code = document.getElementById("otp-code");
  var form = document.getElementById("otp-form");
  if (!code || !form) return;
  var submitted = false;
  code.addEventListener("input", function () {
    var digits = String(code.value || "").replace(/\D/g, "").slice(0, 6);
    if (code.value !== digits) code.value = digits;
    if (digits.length === 6 && !submitted) {
      submitted = true;
      if (typeof form.requestSubmit === "function") form.requestSubmit();
      else form.submit();
    }
  });
})();
