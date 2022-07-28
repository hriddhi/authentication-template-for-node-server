const LocalStrategy = require("passport-local").Strategy;
const { pool } = require("./db-config");
const crypto = require('crypto');
const passport = require('passport')

const authenticateUser = (email, password, done) => {
    pool.query(
        `SELECT * FROM users WHERE email = $1`,
        [email],
        (err, results) => {
            if (err) 
                throw err;

            if (results.rows.length > 0) {
                const user = results.rows[0];
                console.log(user)
                if(user.suspended)
                    return done(null, false, { err: "Your account has been suspended. Please get in touch with the administrator" })

                var hash = crypto.pbkdf2Sync(password, user.salt, 1000, 64, `sha512`).toString(`hex`); 
                if(hash === user.hash)
                    return done(null, user)
                else
                    return done(null, false, { err: "You seem to have entered an incorrect password. Please check and try again" });
            } else {
                return done(null, false, { err: "User doesn't exist. Please check email address and try again" });
            }
        }
    );
};

passport.use(new LocalStrategy({ usernameField: "email", passwordField: "password" }, authenticateUser))

passport.serializeUser((user, done) => {
    console.log('passport.serializeUser')
    done(null, user)
});

passport.deserializeUser((user, done) => {
    console.log('passport.deserializeUser')
    pool.query(`SELECT * FROM users WHERE id = $1`, [user.id], (err, results) => {
        if (err) {
            return done(err);
        }
        console.log(`ID is ${results.rows[0].id}`);
        return done(null, results.rows[0]);
    })
})

module.exports = passport