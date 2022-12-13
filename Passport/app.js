require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const ejs = require('ejs');
const bodyParser = require('body-parser');

// auth
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended:true}));
app.set('view engine',ejs);
const viewsPath = __dirname+'/views/';

// ******* USE EXPRESS SESSION BETWEEN APP.USE AND MONGOOSE *********
// session
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
}))

// passport
app.use(passport.initialize());
app.use(passport.session());

// -----------------------------------------------------------

mongoose.set('strictQuery',true);
mongoose.connect('mongodb://localhost:27017/Secrets');

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model('User',userSchema);

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

passport.use(new GoogleStrategy(
    {
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: 'http://localhost:3000/auth/google/callback',
        userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
        passReqToCallback   : true
    },
    function(accessToken, refreshToken, profile, cb)
    {
        User.findOrCreate({googleId: profile.id}, (err,user) => {
            return done(err, user);
        });
    }
));

// -----------------------------------------------------------

app.get('/',(req,res) => {
    res.render(viewsPath+'home.ejs');
})

app.get('/secrets',(req,res) => {
    if(req.isAuthenticated()) res.render(viewsPath+'secrets.ejs');
    else res.redirect('/login');
})

app.get('/register',(req,res) => {
    res.render(viewsPath+'register.ejs');
})

app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'profile' ] }
));

app.get( '/auth/google/callback',
    passport.authenticate( 'google', {
        successRedirect: '/auth/google/success',
        failureRedirect: '/auth/google/failure'
}));

app.post('/register',(req,res) => {
    User.register({username: req.body.username}, req.body.password, (err,user) => {
        if(err){
            console.log(err);
            res.redirect('/register');
        } else{
            passport.authenticate('local')(req,res,() => {
                res.redirect('/secrets');
            })
        }
    });
})

app.get('/login',(req,res) => {
    res.render(viewsPath+'login.ejs');
})

app.post('/login',(req,res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password,
    });

    req.login(user, (err) => {
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate('local')(req,res, () => {
                res.redirect('/secrets');
            })
        }
    })
})

app.get('/logout',(req,res) => {
    req.logout((err) => {
        if(err) console.log(err);
    })
    res.redirect('/');
})

// -----------------------------------------------------------

app.listen(3000,() => console.log('Server started on port 3000'));