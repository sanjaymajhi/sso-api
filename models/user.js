const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const User = new Schema({
  f_name: { type: String, required: true },
  l_name: { type: String, required: true },
  email: { type: String, required: true },
  password: { type: String, required: this.method === "native" ? true : false },
  location: { type: String, min: 1, max: 40, default: null },
  join_date: { type: Date, default: Date.now },
  last_login: { type: Date, default: Date.now },
  isLoggedIn: { type: Boolean, default: false },
});

module.exports = mongoose.model("sso", User);
