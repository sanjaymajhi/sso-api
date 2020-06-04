var express = require("express");
var router = express.Router();

var userController = require("../controllers/userController");

var auth = require("../auth");

/* GET users listing. */
router.post("/login", userController.login);
router.post("/register", userController.register);
router.post("/update", auth, userController.user_update);
router.post("/updatePassword", auth, userController.change_pass);

module.exports = router;
