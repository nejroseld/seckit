export function render(value) {
  return eval(value);
}

export function lookup(db, req) {
  return db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
}

export function redirect(req, res) {
  return res.redirect(req.query.next);
}

export const corsOptions = cors({ origin: true, credentials: true });
