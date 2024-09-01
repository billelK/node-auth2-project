const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const bcrypt = require("bcryptjs")
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken")
const model = require("../users/users-model")

router.post("/register", validateRoleName, (req, res, next) => {
  model.add(req.body)
    .then(newUser => {
      res.status(201).json(newUser)
    })
    .catch(next)
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {// eslint-disable-line
  const {username, password} = req.body
  const user = req.user
  if (password && bcrypt.compareSync(password,user.password)) {
    const token = tokenMaker(user)
    res.status(200).json({
      message: `${username} is back!`,
      token: token
    }) 
  } else {
    res.status(401).json({
      message: "Invalid credentials"
    })
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function tokenMaker (user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role: user.role_name
  }
  const options = {
    expiresIn: "1d",
  }
return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
