var async = require("async");
var bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken");
var validator = require("express-validator");

var User = require("../models/user");

exports.register = [
  validator
    .body("f_name", "First Name should have min 2 and max 20 characters")
    .trim()
    .isLength({ min: 2, max: 20 }),
  validator
    .body("l_name", "Last Name should have min 2 and max 20 characters")
    .trim()
    .isLength({ min: 2, max: 20 }),
  validator
    .body("password", "password length min 8 and max 15")
    .trim()
    .isLength({ min: 8, max: 15 }),
  validator
    .body("location", "location should be min 2 and max 30 char long")
    .trim()
    .isLength({ min: 2, max: 30 }),
  validator.body("email", "Invalid Email").trim().isEmail(),

  (req, res) => {
    const errors = validator.validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({
        saved: "unsuccessful",
        errors: errors.array(),
      });
      return;
    }

    User.findOne({ email: req.body.email }, "email").exec(
      async (err, email) => {
        if (err) {
          throw err;
        }
        if (email) {
          res.status(400).json({
            saved: "unsuccessful",
            error: { msg: "Email already exists" },
          });
          return;
        } else {
          var salt = await bcrypt.genSalt(10);
          var password = await bcrypt.hash(req.body.password, salt);

          var user = new User({
            f_name:
              req.body.f_name.charAt(0).toUpperCase() +
              req.body.f_name.slice(1),
            l_name:
              req.body.l_name.charAt(0).toUpperCase() +
              req.body.l_name.slice(1),
            password: password,
            email: req.body.email,
            location: req.body.location,
          });

          await user.save((err) => {
            if (err) {
              throw err;
            }

            res.status(200).end();
          });
        }
      }
    );
  },
];

exports.user_update = [
  validator
    .body("f_name", "First Name should be min 2 and max 20 characters long.")
    .trim()
    .isLength({ min: 2, max: 20 }),
  validator
    .body("l_name", "Last Name should be min 2 and max 20 characters long.")
    .trim()
    .isLength({ min: 2, max: 20 }),
  validator
    .body("username", "Username should be min 5 and max 20 characters long.")
    .trim()
    .isLength({ min: 5, max: 20 })
    .isAlphanumeric()
    .withMessage("Only Alpha numeric charcaters allowed in username"),
  validator
    .body("location", "Location should be min 2 and max 30 characters long.")
    .trim()
    .isLength({ min: 2, max: 30 }),

  (req, res) => {
    const errors = validator.validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({
        errors: errors.array(),
      });
      return;
    }

    async.parallel(
      {
        emailCheck: (callback) =>
          User.findOne({ email: req.body.email }).exec(callback),
        user_details: (callback) =>
          User.findById(req.user_detail.id).exec(callback),
      },
      (err, result) => {
        if (err) {
          throw err;
        }
        const emailCheck = result.emailCheck;
        const user_details = result.user_details;
        if (
          emailCheck != undefined &&
          user_details.email !== emailCheck.email
        ) {
          res.status(400).json({
            error: { msg: "Email already exists..." },
          });
          return;
        } else {
          User.findById(req.user_detail.id).exec(async (err, result) => {
            if (err) {
              throw err;
            }
            var userCopy = {
              ...result._doc,
              f_name:
                req.body.f_name.charAt(0).toUpperCase() +
                req.body.f_name.slice(1),
              l_name:
                req.body.l_name.charAt(0).toUpperCase() +
                req.body.l_name.slice(1),
              location: req.body.location,
              email: req.body.email,
            };
            var user = new User(userCopy);
            await User.findByIdAndUpdate(user._id, user, (err) => {
              if (err) {
                throw err;
              }
              res.status(200).end();
            });
          });
        }
      }
    );
  },
];

exports.login = [
  validator
    .body("email", "Invalid Email or Password")
    .isLength({ min: 5 })
    .trim()
    .isEmail(),
  validator.body("password", "Invalid Password").isLength({ min: 5 }).trim(),

  (req, res) => {
    if (req.body.method === "native") {
      const errors = validator.validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          errors: errors.array(),
        });
        return;
      }
    }

    User.findOne({ email: req.body.email }).exec(async (err, result) => {
      if (err) {
        throw err;
      }
      if (!result) {
        res.status(400).json({
          error: { msg: "Email does not exists" },
        });
        return;
      } else {
        const isMatch = await bcrypt.compare(
          req.body.password,
          result.password
        );

        if (!isMatch) {
          res.status(400).json({
            error: { msg: "Incorrect password" },
          });
          return;
        }

        var payload = {
          user: {
            id: result._id,
          },
        };
        await jwt.sign(
          payload,
          "sanjay",
          { expiresIn: 3600 }, //valid till 1 hour
          async (err, token) => {
            if (err) {
              throw err;
            }
            var userCopy = {
              ...result._doc,
              last_login: Date.now(),
              isLoggedIn: true,
            };
            await User.findByIdAndUpdate(userCopy._id, userCopy, {}, (err) => {
              if (err) {
                throw err;
              }
            });
            res.status(200).json({
              token: token,
              ssoUserId: result._id,
              f_name: result.f_name,
              l_name: result.l_name,
              email: result.email,
            });
          }
        );
      }
    });
  },
];

exports.change_pass = [
  validator
    .body("c_pass", "old password cannot be empty")
    .isLength({ min: 1 })
    .trim(),
  validator
    .body("n_pass", "new password length min 8 and max 15")
    .isLength({ min: 8, max: 15 })
    .trim(),

  (req, res) => {
    const errors = validator.validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ error: errors.array() });
      return;
    }
    User.findById(req.user_detail.id).exec(async (err, result) => {
      if (err) {
        throw err;
      }
      if (!result) {
        res.status(400).json({
          error: { msg: "user does not exist" },
        });
        return;
      } else {
        const isMatch = await bcrypt.compare(req.body.c_pass, result.password);
        if (!isMatch) {
          res.status(400).json({
            error: { msg: "Incorrect password" },
          });
          return;
        } else {
          var salt = await bcrypt.genSalt(10);
          var password = await bcrypt.hash(req.body.n_pass, salt);
          var userCopy = { ...result._doc, password: password };
          var user = new User(userCopy);
          await User.findByIdAndUpdate(user._id, user, (err) => {
            if (err) {
              throw err;
            }
            res.status(200).end();
          });
        }
      }
    });
  },
];
