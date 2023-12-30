const express = require("express");
const mongoose = require("mongoose");
require("dotenv").config();

const userRoutes = require("./routes/user.routes");

const app = express();
app.use(express.json());

app.use("/user", userRoutes);

app.listen(process.env.PORT, () => {
  console.log(`App started on port ${process.env.PORT}`);
});

mongoose.connect("mongodb://mongo_base:27017/").then((e) => {
  console.log("Connected to mongodb");
});
