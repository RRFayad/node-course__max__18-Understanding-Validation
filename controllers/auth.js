const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const sgMail = require("@sendgrid/mail");
const { validationResult } = require("express-validator");

const User = require("../models/user");

require("dotenv").config();

// const transporter = nodemailer.createTransport(
//   sendgridTransport({
//     auth: {
//       api_key: process.env.SENDGRID_API_KEY,
//     },
//   })
// );

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

exports.getLogin = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: message,
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: message,
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  User.findOne({ email })
    .then((user) => {
      if (!user) {
        req.flash("error", "E-mail not found");
        res.redirect("/login");
      }
      bcrypt
        .compare(password, user.password) // return boolean
        .then((passwordDoesMatch) => {
          if (passwordDoesMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save((err) => {
              console.log(err);
              res.redirect("/");
            });
          }
          return res.redirect("/login");
        })
        .catch((err) => {
          console.log(err);
          res.redirect("/login");
        });
    })
    .catch((err) => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;
  // We are not going to work in validation right now, but this should be done (we will work on this in the future)
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    console.log(errors.array());
    return res
      .status(422) // 422 is a regular res status for validation errors
      .render("auth/signup", {
        path: "/signup",
        pageTitle: "Signup",
        errorMessage: errors.array(),
      });
  }

  User.findOne({ email: email }).then((userDoc) => {
    if (userDoc) {
      req.flash("error", "E-mail already registered");
      return res.redirect("/signup");
    }
    return bcrypt
      .hash(password, 12) // 12 is a standard value here, it's the number of rounds of encrypting
      .then((hashedPassword) => {
        const user = new User({
          email: email.trim(),
          password: hashedPassword,
          cart: { items: [] },
        });
        return user.save();
      })
      .then((result) => {
        res.redirect("/login");
        console.log(email);
        return sgMail
          .send({
            to: email,
            from: "renan.fayad@rrfayad.com",
            subject: "Sign Up Suceeded",
            text: "Ihaaaaa",
            html: "<h1> You successfully signed up! </h1>",
          })
          .then((result) => console.log("Email sent?", result))
          .catch((err) => console.log(err));
      })
      .catch((err) => {
        console.log(err);
      });
  });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.log(err);
    res.redirect("/");
  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/reset", {
    path: "/reset",
    pageTitle: "Reset Password",
    errorMessage: message,
  });
};

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect("/reset");
    }
    const token = buffer.toString("hex");
    User.findOne({ email: req.body.email }).then((user) => {
      if (!user) {
        req.flash("error", "Email not found");
        return res.redirect("/reset");
      }
      if (user) {
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000; // Expiration = Now + 1 hour (in miliseconds)
        res.redirect("/login");
        return user
          .save()
          .then((result) => {
            sgMail
              .send({
                to: req.body.email,
                from: "renan.fayad@rrfayad.com",
                subject: "Password Reset",
                text: "Ihaaaaa",
                html: `
                <p>You requested a Password reset! </p>
                <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password </p>
                `,
              })
              .then((result) => "Email sent (?)")
              .catch((err) => console.log(err));
          })
          .catch((err) => {
            console.log(err);
          });
      }
    });
  });
};

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({
    resetToken: token,
    resetTokenExpiration: { $gt: Date.now() },
  })
    .then((user) => {
      let message = req.flash("error");
      if (message.length > 0) {
        message = message[0];
      } else {
        message = null;
      }
      res.render("auth/new-password", {
        path: "/new-password",
        pageTitle: "New Password",
        errorMessage: message,
        userId: user._id.toString(),
        passwordToken: token,
      });
    })
    .catch((err) => console.log(err)); // $gt is a greater than operation
};

exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const token = req.body.passwordToken;
  User.findOne({
    resetToken: token,
    resetTokenExpiration: { $gt: Date.now() },
    _id: userId,
  })
    .then((user) => {
      if (!user) {
        req.flash("error", "Please try again!");
        return res.redirect("/reset");
      } else {
        return bcrypt
          .hash(newPassword, 12)
          .then((hashedPassword) => {
            user.password = hashedPassword;
            user.resetToken = undefined;
            user.resetTokenExpiration = undefined;
            res.redirect("/login");
            return user.save();
          })
          .catch((err) => console.log(err));
      }
    })
    .catch((err) => console.log(err));
};
