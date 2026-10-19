const ICONS = {
  folder: '<path d="M2 4.5h4l1.5 2H14v7H2z"/>',
  download: '<path d="M8 2v7m0 0 3-3m-3 3L5 6"/><path d="M2.5 11v2.5h11V11"/>',
  search: '<circle cx="7" cy="7" r="4.2"/><path d="M10.2 10.2 14 14"/>',
  plus: '<path d="M8 3v10M3 8h10"/>',
  list: '<path d="M5 4.5h9M5 8h9M5 11.5h9M2.5 4.5h.01M2.5 8h.01M2.5 11.5h.01"/>',
  clock: '<circle cx="8" cy="8" r="5.5"/><path d="M8 5v3l2 1.5"/>',
  grid: '<rect x="2.5" y="2.5" width="4.5" height="4.5"/><rect x="9" y="2.5" width="4.5" height="4.5"/><rect x="2.5" y="9" width="4.5" height="4.5"/><rect x="9" y="9" width="4.5" height="4.5"/>',
  chevronRight: '<path d="M6 3.5 10.5 8 6 12.5"/>',
  cancel: '<path d="M4 4l8 8M12 4l-8 8"/>',
  sun: '<circle cx="8" cy="8" r="3"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8h1.5M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M12.6 3.4l-1 1M4.4 11.6l-1 1"/>',
  moon: '<path d="M13 9.5A5.5 5.5 0 0 1 6.5 3 5.5 5.5 0 1 0 13 9.5z"/>',
};

export function icon(name) {
  const body = ICONS[name] || "";
  return `<svg class="ico" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}
