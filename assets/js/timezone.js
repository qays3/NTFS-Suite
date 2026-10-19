const ZERO = "1601-01-01T00:00:00.0000000Z";

let current = "UTC";

export function allZones() {
  let zones = [];
  try {
    if (typeof Intl.supportedValuesOf === "function") {
      zones = Intl.supportedValuesOf("timeZone");
    }
  } catch (e) {
    void e;
  }
  if (!zones || zones.length === 0) {
    zones = [
      "UTC", "Africa/Cairo", "America/New_York", "America/Chicago", "America/Denver",
      "America/Los_Angeles", "America/Sao_Paulo", "Asia/Amman", "Asia/Dubai", "Asia/Riyadh",
      "Asia/Kolkata", "Asia/Shanghai", "Asia/Tokyo", "Australia/Sydney", "Europe/London",
      "Europe/Paris", "Europe/Berlin", "Europe/Moscow", "Pacific/Auckland",
    ];
  }
  return ["UTC", "local", ...zones.filter((z) => z !== "UTC")];
}

export function setZone(zone) {
  current = zone;
}

export function activeZone() {
  return current;
}

export function resolvedZone() {
  if (current === "local") {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  }
  return current;
}

export function isZero(iso) {
  return !iso || iso === ZERO;
}

export function format(iso) {
  if (isZero(iso)) {
    return "";
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  const zone = resolvedZone();
  const fraction = iso.slice(20, 27);
  if (current === "UTC") {
    return iso.slice(0, 19).replace("T", " ") + "." + fraction;
  }
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: zone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(date);
  const get = (t) => parts.find((p) => p.type === t)?.value || "00";
  const text =
    get("year") + "-" + get("month") + "-" + get("day") + " " +
    get("hour") + ":" + get("minute") + ":" + get("second") + "." + fraction;
  return text;
}

export function hasZeroSubseconds(iso) {
  if (isZero(iso)) {
    return false;
  }
  return iso.slice(20, 27) === "0000000";
}

export function siBeforeFn(si, fn) {
  if (isZero(si) || isZero(fn)) {
    return false;
  }
  return si < fn;
}
