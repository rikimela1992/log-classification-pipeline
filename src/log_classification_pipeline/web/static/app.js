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
    window.alert("The session protection token is missing. Reload the page.");
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
      let message = "The operation failed closed.";
      try {
        const problem = await response.json();
        message = problem.detail || message;
      } catch (_error) {
        // Keep the generic message.
      }
      window.alert(message);
    }
  } catch (_error) {
    window.alert("The local service could not be reached. No success was assumed.");
  } finally {
    delete form.dataset.submitting;
    controls.forEach((control) => { control.disabled = false; });
  }
});
