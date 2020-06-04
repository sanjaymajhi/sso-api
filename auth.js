var jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  const token = req.headers.authorization.split(" ")[1];
  if (!token) {
    res.statusMessage = "Dont try to cheat.";
    res.status(403).end();
    return;
  }
  try {
    const decoded = jwt.verify(token, "sanjay");
    req.user_detail = decoded.user;
    next();
  } catch {
    res.statusMessage = "Invalid Token.";
    res.status(500).end();
  }
};
