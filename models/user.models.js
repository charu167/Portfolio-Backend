const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  email: { type: String },
  password: { type: String },
});

// userSchema.pre("save", async (next) => {
//   const salt = await bcrypt.genSalt();
//   this.password = await bcrypt.hash(this.password, salt);
//   next();
// });

const User = mongoose.model("User", userSchema);

module.exports = { User };
