var express = require('express');
var crypto = require('crypto')

var router = express.Router();

var passport = require('../passport-config')
const { pool } = require('../db-config')

/* GET test route. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    console.log(info)
    if(err)
      return next(err)
    if(!user)
      return res.status(401).json({ err: info.err })
    req.logIn(user, err => {
      if(err) return next(err)
      return res.status(200)
        .json({
          session: true,
          user: { id: user.id, name: user.name, email: user.email, role: user.role }
        }) 
    })
  })(req, res, next);
})

router.get('/login/failed', (req, res) => {
  res.status(401).json({ session: false, user: null })
})

checkAuth = (req, res, next) => {
  if(!req.isAuthenticated() || req.user.suspended)
    return res.status(401).json({ session: false, user: null })
  next()
}

router.get("/logout", checkAuth, (req, res) => {
  req.logout()
  res.status(200).json({ session: false, user: null })
})

router.get("/check", checkAuth, (req, res) => {
  res.status(200).json({ session: true, user: { name: req.user.name, email: req.user.email, role: req.user.role } })
})

/* POST register users */
router.post('/register', (req, res) => {
  let { name, email, password, confirm_password, role, passcode } = req.body
  console.log({ name, email, password, confirm_password, role, passcode })

  var errors = []

  if (!name || !email || !password || !confirm_password)
    errors.push("Please enter all fields" )
  if (password && password !== '') {
    if (password.length < 6)
      errors.push("Password must be a least 6 characters long" )
    if (password.length > 20)
      errors.push("Password cannot exceed 20 characters" )
  }

  if(errors.length > 0){
    return res.status(400).json({ err: errors.join(' • ') })
  } 

  let salt = crypto.randomBytes(16).toString('hex')
  let hash = crypto.pbkdf2Sync(password, salt, 1000, 64, `sha512`).toString(`hex`)
  
  console.log({ salt, hash })

  if(role == 0 || role == 1) {
    if(role == 1 && passcode != 'passcode')
      return res.status(400).json({ err: 'Invalid Passcode' })

    pool.query(
      `INSERT INTO users (name, email, role, salt, hash) VALUES ($1, $2, $3, $4, $5) RETURNING id, email`,
        [name, email, role, salt, hash],
        (err, results) => {
          if (err)
            return res.status(400).json({ err: err.detail })
          console.log(results.rows);
          res.status(201).json({ message: `${ role == 0 ? 'Admin' : 'Volunteer' } registered successfully.` })
        }
    )
  } else 
    return res.status(400).json({ err: 'Invalid role.' })
})

module.exports = router;
