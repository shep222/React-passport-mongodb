const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const brcypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keys = require('../../config/keys');
const passport = require('passport');


// Load User Model
const User = require('./../models/User');


// @route GET api/users/test
// @desc Tests users route
// @access Public
router.get('/test', (req, res) => res.json({
  msg: "Users Works"
}));

// @route GET api/users/register
// @desc Register User
// @access Public
router.post('/register', (req, res) => {
  User.findOne({
    email: req.body.email
  }).then(user => {
    if (user) {
      console.log('FAIL')
      return res.status(400).json({
        email: 'Email already exists;'
      })
    } else {
      console.log('PASS')
      const avatar = gravatar.url(req.body.email, {
        s: '200', // size
        r: 'pg', // rating
        d: 'mm' // default image
      })

      const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        avatar,
        password: req.body.password
      })

      brcypt.genSalt(10, (err, salt) => {
        brcypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          newUser.save()
            .then(user => res.json(user))
            .catch(err => console.log(err))
        })
      })
    }
  })
})

// @route GET api/users/login
// @desc Login User / Return JWT Token
// @access Public
router.post('/login', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  //Find user email
  User.findOne({
      email
    })
    .then(user => {
      //Check for user
      if (!user) {
        return res.status(404).json({
          email: 'User not found'
        })
      }

      //Check Password
      brcypt.compare(password, user.password)
        .then(isMatch => {
          if (isMatch) {
            //User Matched
            const payload = {
              id: user.id,
              name: user.name,
              avatar: user.avatar
            } //Create JWT Payload

            //Sign Webtoken
            jwt.sign(
              payload,
              keys.secretOrKey, {
                expiresIn: 3600 //in seconds
              },
              (err, token) => {
                res.json({
                  success: true,
                  token: 'Bearer ' + token
                });
              })
          } else {
            return res.status(400).json({
              password: 'Password Incorrect'
            })
          }
        })
    })
})

// @route GET api/users/current
// @desc Return current User
// @access Private
router.get('/current', passport.authenticate('jwt', {
  session: false
}), (req, res) => {
  res.json(req.user.name)
});


module.exports = router;