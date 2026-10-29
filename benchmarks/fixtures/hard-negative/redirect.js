// Safe allowlist, deliberately testing a flow guard that CE may not understand.
export function redirect(req, res) {
  const destinations = new Set(["/home", "/account"]);
  const next = destinations.has(req.query.next) ? req.query.next : "/home";
  return res.redirect(next);
}
