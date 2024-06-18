const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


const userSchema = new mongoose.Schema({
    email: {
      type: String,
      required: true,
      unique: true
    },
    password: {
      type: String,
    },
    googleId: {
      type: String,
      unique: true,
      sparse: true
    },
    name: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    tokens: [
      {
          token:{
              type: String,
              required:true
          }
      }
    ]
  });


  userSchema.pre("save" , async function (next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash( this.password, 12);
    }
    next();
});

userSchema.pre("save" , async function (next) {
  if (this.isModified('googleId')) {
      this.googleId = await bcrypt.hash( this.googleId, 12);
  }
  next();
});

// generating auth token
userSchema.methods.generateAuthToken = async function() {
    try{
        let token = jwt.sign({_id:this._id}, process.env.SECRET_KEY); 
        this.tokens = this.tokens.concat(({ token:token }));
        await this.save();
        return token;

    }catch(err){
        console.log(err);
    }
}

const User = mongoose.model('User', userSchema);

module.exports = User;