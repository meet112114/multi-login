const dotenv = require("dotenv");
const express = require('express');
const session = require('express-session');
const passport = require('./router/passport'); // Corrected path
dotenv.config({path:"./config.env"});

const app = express();

app.use(session({
    resave: false,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET || 'secrethere'
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(require('./router/auth'));

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server is running at port number ${PORT}`);
});