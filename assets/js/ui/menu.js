let activeMenu = null;

export function openMenu(anchor, contentNode) {
  closeMenu();
  const menu = document.createElement("div");
  menu.className = "menu-pop";
  menu.appendChild(contentNode);
  document.body.appendChild(menu);
  const r = anchor.getBoundingClientRect();
  menu.style.top = r.bottom + 4 + "px";
  menu.style.left = Math.max(8, r.right - menu.offsetWidth) + "px";
  activeMenu = menu;
  const onDoc = (e) => {
    if (!menu.contains(e.target) && e.target !== anchor) {
      closeMenu();
    }
  };
  menu._onDoc = onDoc;
  setTimeout(() => document.addEventListener("mousedown", onDoc), 0);
}

export function closeMenu() {
  if (activeMenu) {
    document.removeEventListener("mousedown", activeMenu._onDoc);
    activeMenu.remove();
    activeMenu = null;
  }
}
