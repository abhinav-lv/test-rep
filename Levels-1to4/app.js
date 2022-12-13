//jshint esversion:6
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');

// lvl-2
const encrypt = require('mongoose-encryption');

// lvl-3
// const md5 = require('md5');

// lvl-4
const bcrypt = require('bcrypt');
const saltRounds = 10;

const ejs = require('ejs');
const bodyParser = require('body-parser');

const app = express();
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));
app.set('view engine', ejs);

mongoose.set('strictQuery',true);
mongoose.connect('mongodb://localhost:27017/Secrets');
// -------------------------------------------------------------------

// console.log(process.env.API_KEY);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
})

// lvl-2
userSchema.plugin(encrypt,{secret: process.env.SECRET, encryptedFields: ['password']});
  
const User = new mongoose.model("User",userSchema);

// -------------------------------------------------------------------

app.get('/',(req,res) => {
    res.render(__dirname+'/views/home.ejs');
});

app.get('/login',(req,res) => {
    res.render(__dirname+'/views/login.ejs');
});

app.get('/register',(req,res) => {
    res.render(__dirname+'/views/register.ejs');
});

app.post('/register',(req,res) => {

    bcrypt.hash(req.body.password, saltRounds, (err,hash) => {
        const newUser = new User({
            email: req.body.username,
            password: hash,
        })
    
        newUser.save((err) => {
            if(err) console.log(err);
            else res.render(__dirname+'/views/secrets.ejs');
        })
    })
});

app.post('/login',(req,res) => {
    const email = req.body.username;
    const pass = req.body.password; // lvl-3
    
    User.findOne({email: email}, (err,foundUser) => {
        if(err) console.log(err);
        else{
            if(foundUser){
                bcrypt.compare(pass,foundUser.password,(error,result) => {
                    if(result === true){
                        res.render(__dirname+'/views/secrets.ejs');
                    }
                    else{
                        res.send('There was an error');
                    }
                })
            }
            else res.redirect('/login');
        }
    })
})

app.get('/logout',(req,res) => {
    res.redirect('/');
});

// -------------------------------------------------------------------
app.listen(3000, () => console.log("Server started on port 3000."));