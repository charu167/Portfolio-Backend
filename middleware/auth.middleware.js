const zod = require("zod");
const jwt = require("jsonwebtoken");

function zodMiddleware(req, res, next) {
  try {
    const email = req.body.email;
    const password = req.body.password;

    const emailSchema = zod.string().email();
    const passwordSchema = zod.string().min(6);

    if (
      emailSchema.safeParse(email).success &&
      passwordSchema.safeParse(password).success
    ) {
      next();
    } else {
      res.status(400).json({ error: "Invalid email/password" });
    }
  } catch (error) {
    res.status(500).json(error);
  }
}

function jwtVerify(req, res, next) {
  try {
    const token = req.headers.authorization;
    const decoded = jwt.verify(token, process.env.jwtPassword);
    if (decoded) {
      next();
    } else {
      res.status(500).json({ error: "The user is NOT authenticated" });
    }
  } catch (error) {
    res.status(500).json(error);
  }
}

module.exports = { zodMiddleware, jwtVerify };
