document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-secure-form")) {
    return;
  }
  event.preventDefault();
  if (form.dataset.submitting === "true") {
    return;
  }
  const confirmation = form.getAttribute("data-confirm");
  if (confirmation && !window.confirm(confirmation)) {
    return;
  }
  const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");
  if (!csrf) {
    window.alert(document.body.dataset.csrfMissing);
    return;
  }
  form.dataset.submitting = "true";
  const controls = Array.from(form.querySelectorAll('button[type="submit"], input[type="submit"]'));
  controls.forEach((control) => { control.disabled = true; });
  try {
    const response = await fetch(form.action, {
      method: form.method || "POST",
      body: new FormData(form),
      credentials: "same-origin",
      headers: {"X-CSRF-Token": csrf},
    });
    if (response.redirected) {
      window.location.assign(response.url);
      return;
    }
    if (!response.ok) {
      let message = document.body.dataset.operationFailed;
      try {
        const problem = await response.json();
        const localized = {
          invalid_credentials: document.body.dataset.errorInvalidCredentials,
          input_too_large: document.body.dataset.errorInputTooLarge,
          request_too_large: document.body.dataset.errorInputTooLarge,
          model_busy: document.body.dataset.errorModelBusy,
        };
        message = localized[problem.code] || message;
      } catch (_error) {
        // Keep the generic message.
      }
      window.alert(message);
    }
  } catch (_error) {
    window.alert(document.body.dataset.serviceUnreachable);
  } finally {
    delete form.dataset.submitting;
    controls.forEach((control) => { control.disabled = false; });
  }
});
