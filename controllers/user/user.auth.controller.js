const { User } = require("../../models/user.models");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

async function signup(req, res) {
  try {
    const email = req.body.email;
    const password = await bcrypt.hash(req.body.password, 10);

    const newUser = new User({
      email: email,
      password: password,
    });

    newUser
      .save()
      .then((doc) => {
        res.status(200).json(doc);
      })
      .catch((error) => {
        res.status(400).json(error);
      });
  } catch (error) {
    res.status(400).json(error);
  }
}

async function signin(req, res) {
  try {
    const email = req.body.email;
    const password = req.body.password;

    const user = await User.findOne({ email: email });

    const isMatch = await bcrypt.compare(password, user.password);

    if (user) {
      if (isMatch) {
        const token = await jwt.sign(
          { email, password },
          process.env.jwtPassword
        );
        res.status(200).json({
          token: token,
        });
      } else {
        res.status(400).json({ error: "Password doesn't match" });
      }
    } else {
      res.status(400).json({ error: "User not found" });
    }
  } catch (error) {
    res.status(400).json(error);
  }
}

function authenticated(req, res) {
  res
    .status(200)
    .json({ message: "The user is authenticated to access this API" });
}

module.exports = { signup, signin, authenticated };
