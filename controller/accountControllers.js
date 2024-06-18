const bcrypt = require('bcrypt');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const LoginAuth = require('../middleware/jwtmiddleware');

// Controller for handling google registration
const googleRoute = async (req, res) => {
    if (req.user) {
        const email = req.user.emails[0].value;
        const googleId = req.user.id;
        const name = req.user.displayName;
        console.log(email);
        
        const user = await User.findOne({ email });
        if (!user) {
            try {
                const newUser = new User({ email, googleId, name });
                await newUser.save();
                console.log('User saved successfully.');
            } catch (error) {
                console.error('Error saving user:', error);
                throw error;
            }
        } else if (user.password) {
            res.json({ Message: 'User Email Exists with register' });
        } else {
            const userLogin = await User.findOne({ email });
            if (userLogin) {
                const isMatch = await bcrypt.compare(googleId, userLogin.googleId);
                const token = await userLogin.generateAuthToken();
                console.log(token);
                res.cookie("jwtoken", token, {
                    expires: new Date(Date.now() + 2589200000),
                    httpOnly: true
                });

                if (!isMatch) {
                    res.status(400).json({ error: "Invalid credentials" });
                } else {
                    res.json({ message: "User login successfully" });
                }
            } else {
                res.status(400).json({ error: "Invalid credentials" });
            }
        }
    } else {
        res.json({ message: "Error logging in, try again later" });
    }
};


// Controller for handling normal registration
const registerRoute = async (req, res) => {
    if (req.body) {
        const { email, name, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            try {
                const newUser = new User({ email, password, name });
                await newUser.save();
                console.log('User saved successfully.');
            } catch (error) {
                console.error('Error saving user:', error);
                throw error;
            }
        } else if (user.googleId) {
            res.json({ Message: 'User Email Exists with google' });
        } 
    } else {
        res.json({ message: "Error logging in, try again later" });
    }
};

const loginRoute = async (req , res ) => {
    const email = req.body.email ;
    const password = req.body.password ;

    const userLogin = await User.findOne({ email });
            if (userLogin) {
                const isMatch = await bcrypt.compare(password, userLogin.password);
                const token = await userLogin.generateAuthToken();
                console.log(token);
                res.cookie("jwtoken", token, {
                    expires: new Date(Date.now() + 2589200000),
                    httpOnly: true
                });

                if (!isMatch) {
                    res.status(400).json({ error: "Invalid credentials" });
                } else {
                    res.json({ message: "User login successfully" });
                }
            } else {
                res.status(400).json({ error: "Invalid credentials" });
            }
} 


module.exports = { googleRoute, registerRoute , loginRoute };