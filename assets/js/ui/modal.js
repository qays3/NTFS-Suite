export function openModal(options) {
  const opts = options || {};
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  const modal = document.createElement("div");
  modal.className = "modal";
  if (opts.width) {
    modal.style.maxWidth = opts.width;
  }
  const head = document.createElement("div");
  head.className = "modal-head";
  const title = document.createElement("span");
  title.textContent = opts.title || "";
  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "btn ghost small";
  closeBtn.textContent = "Close";
  head.appendChild(title);
  head.appendChild(closeBtn);
  const body = document.createElement("div");
  body.className = "modal-body";
  modal.appendChild(head);
  modal.appendChild(body);
  backdrop.appendChild(modal);
  document.body.appendChild(backdrop);

  const close = () => {
    backdrop.remove();
    document.removeEventListener("keydown", onKey);
    if (typeof opts.onClose === "function") {
      opts.onClose();
    }
  };
  const onKey = (e) => {
    if (e.key === "Escape") {
      close();
    }
  };
  closeBtn.addEventListener("click", close);
  backdrop.addEventListener("click", (e) => {
    if (e.target === backdrop) {
      close();
    }
  });
  document.addEventListener("keydown", onKey);

  return { backdrop, body, close };
}

export function confirmDialog(message, confirmLabel, danger) {
  return new Promise((resolve) => {
    const m = openModal({ title: "Confirm", width: "400px" });
    const p = document.createElement("p");
    p.className = "confirm-msg";
    p.textContent = message;
    const foot = document.createElement("div");
    foot.className = "modal-foot";
    const no = document.createElement("button");
    no.type = "button";
    no.className = "btn ghost small";
    no.textContent = "Cancel";
    const yes = document.createElement("button");
    yes.type = "button";
    yes.className = "btn small" + (danger === false ? "" : " danger");
    yes.textContent = confirmLabel || "Confirm";
    foot.appendChild(no);
    foot.appendChild(yes);
    m.body.appendChild(p);
    m.body.appendChild(foot);
    no.addEventListener("click", () => {
      m.close();
      resolve(false);
    });
    yes.addEventListener("click", () => {
      m.close();
      resolve(true);
    });
  });
}
