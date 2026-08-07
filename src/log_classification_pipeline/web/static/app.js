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
          login_rate_limited: document.body.dataset.errorLoginRateLimited,
          input_too_large: document.body.dataset.errorInputTooLarge,
          request_too_large: document.body.dataset.errorInputTooLarge,
          model_busy: document.body.dataset.errorModelBusy,
          queue_full: document.body.dataset.errorModelBusy,
          worker_unavailable: document.body.dataset.errorModelBusy,
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

const monitor = document.querySelector("[data-job-monitor]");
if (monitor instanceof HTMLElement) {
  const progress = monitor.querySelector("[data-progress]");
  const count = monitor.querySelector("[data-progress-count]");
  const state = monitor.querySelector("[data-job-state]");
  let delay = 1000;
  let stopped = false;

  const poll = async () => {
    if (stopped || document.hidden) {
      window.setTimeout(poll, delay);
      return;
    }
    try {
      const response = await fetch(monitor.dataset.statusUrl, {
        credentials: "same-origin",
        headers: {"Accept": "application/json"},
      });
      if (!response.ok) {
        throw new Error("status unavailable");
      }
      const payload = await response.json();
      if (progress instanceof HTMLProgressElement) {
        progress.value = payload.processed_records;
        progress.max = payload.input_records;
      }
      if (count instanceof HTMLElement) {
        count.textContent = `${payload.processed_records} / ${payload.input_records}`;
      }
      const statusKey = `status${payload.status.charAt(0).toUpperCase()}${payload.status.slice(1)}`;
      if (state instanceof HTMLElement && monitor.dataset[statusKey]) {
        state.textContent = monitor.dataset[statusKey];
      }
      delay = 1000;
      if (["succeeded", "failed", "cancelled"].includes(payload.status)) {
        stopped = true;
        window.location.reload();
        return;
      }
    } catch (_error) {
      if (state instanceof HTMLElement) {
        state.textContent = document.body.dataset.serviceUnreachable;
      }
      delay = Math.min(delay * 2, 10000);
    }
    window.setTimeout(poll, delay);
  };
  window.setTimeout(poll, delay);
}
