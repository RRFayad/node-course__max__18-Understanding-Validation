const express = require("express");
const { check, body } = require("express-validator");

const authController = require("../controllers/auth");

const router = express.Router();

router.get("/login", authController.getLogin);

router.get("/signup", authController.getSignup);

router.post("/login", authController.postLogin);

router.post(
  "/signup",
  [
    check("email")
      .isEmail()
      .withMessage("Please Enter a valid e-mail")
      .custom((value, { req }) => {
        // This is a dummy logic, but just to show that we can create our own custom validations
        if (value === "test@test.com") {
          throw new Error("This email address is forbidden");
        }
        return true;
      }),
    body("password", "Please, at least 5 characters and alphaumeric")
      .isLength({ min: 6 }) // body is just an alternative to the check(), we will chec the body of the request
      .isAlphanumeric(),
  ],
  authController.postSignup
);

router.post("/logout", authController.postLogout);

router.get("/reset", authController.getReset);

router.post("/reset", authController.postReset);

router.get("/reset/:token", authController.getNewPassword);

router.post("/new-password", authController.postNewPassword);

module.exports = router;
