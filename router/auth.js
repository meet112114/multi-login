const express = require('express');
const passport = require('./passport');
require('../database/connection');
const router = express.Router();
router.use(express.json());
const cookieParser = require("cookie-parser");
router.use(cookieParser());
const {  googleRoute, registerRoute , loginRoute } = require('../controller/accountControllers');

// google signin ( Oath2.0 ) routes 
router.get('/auth/google', passport.authenticate('google', { scope: ['email', 'profile'] }));
router.get('/auth/google/callback', passport.authenticate('google', { 
    failureRedirect: '/login',
    successRedirect: '/google'
}));

router.get('/google', googleRoute);  // google signin/login route
router.post('/register', registerRoute); // normal signup route 
router.post('/login' , loginRoute);


module.exports = router;