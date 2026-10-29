export function parse(value) {
  return JSON.parse(value);
}

export function lookup(db, req) {
  return db.query("SELECT * FROM users WHERE name = ?", [req.query.name]);
}

export function redirect(req, res) {
  if (req.query.next === "/account") return res.redirect("/account");
  return res.redirect("/home");
}

export const corsOptions = cors({ origin: ["https://app.example.test"], credentials: true });
