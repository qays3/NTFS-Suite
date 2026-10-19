let node = null;
let timer = null;

export function toast(message) {
  if (!node) {
    node = document.createElement("div");
    node.className = "toast";
    document.body.appendChild(node);
  }
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(timer);
  timer = setTimeout(() => {
    if (node) {
      node.classList.remove("show");
    }
  }, 1600);
}
