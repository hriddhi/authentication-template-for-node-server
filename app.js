var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var usersRouter = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

var cors = require('cors')
app.use(cors({ credentials: true, origin: 'http://localhost:3000' }))

var passport = require('./passport-config')
const { pool } = require('./db-config')

var session = require('express-session');
var pgSession = require('connect-pg-simple')(session)

app.use(session({ 
  store: new pgSession({ pool: pool, tableName: 'session', createTableIfMissing: true }),
  secret: 'tcsrapidlabs', 
  resave: true, 
  saveUninitialized: true,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}))

app.use(passport.initialize())
app.use(passport.session())

checkAuth = (req, res, next) => {
  if(!req.isAuthenticated() || req.user.suspended)
    return res.status(401).json({ session: false, user: null })
  next()
}

checkPrevilage = (req, res, next) => {
  console.log(req.user)
  if(req.user.role > 1)
    return res.status(403).json({ err: 'You do not have the previlage to perform this action (PERMISSION_DENIED)' })
  next()
} 

app.use('/users', usersRouter);


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.json({ err: 'Internal Server Error' })
  //res.render('error');
});

module.exports = { app };