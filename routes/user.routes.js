const { Router } = require("express");
const {
  signup,
  signin,
  authenticated,
} = require("../controllers/user/user.auth.controller");

const {
  zodMiddleware,
  jwtVerify,
} = require("../middleware/auth.middleware");

const router = Router();

router.post("/signup", zodMiddleware, signup);
router.post("/signin", zodMiddleware, signin);
router.get("/authenticatedAPI", jwtVerify, authenticated);

module.exports = router;
