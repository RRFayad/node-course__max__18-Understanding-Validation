const express = require("express");
const { check, body } = require("express-validator");

const authController = require("../controllers/auth");
const User = require("../models/user");

const router = express.Router();

router.get("/login", authController.getLogin);

router.get("/signup", authController.getSignup);

router.post(
  "/login",
  [
    body("email")
      .isEmail()
      .withMessage("Please insert a real e-mail")
      .normalizeEmail(),
    body(
      "password",
      "it makes no sense to validate it here, but it's just for the sake of practice"
    )
      .isLength({ min: 6 })
      .isAlphanumeric()
      .trim(),
  ],
  authController.postLogin
);

router.post(
  "/signup",
  [
    check("email")
      .isEmail()
      .withMessage("Please Enter a valid e-mail")
      .custom((value, { req }) => {
        // if (value === "test@test.com") {         // This is a dummy logic, but just to show that we can create our own custom validations
        //   throw new Error("This email address is forbidden");
        // }
        // return true;
        return User.findOne({ email: value }).then((userDoc) => {
          if (userDoc) {
            return Promise.reject("E-mail already exists!");
          }
        });
      })
      .normalizeEmail(),
    body("password", "Please, at least 6 characters and alphaumeric")
      .isLength({ min: 6 }) // body is just an alternative to the check(), we will chec the body of the request
      .isAlphanumeric()
      .trim(),
    body("confirmPassword").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords do not match");
      }
      return true;
    }),
  ],
  authController.postSignup
);

router.post("/logout", authController.postLogout);

router.get("/reset", authController.getReset);

router.post("/reset", authController.postReset);

router.get("/reset/:token", authController.getNewPassword);

router.post("/new-password", authController.postNewPassword);

module.exports = router;
