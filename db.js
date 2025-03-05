const mongoose = require('mongoose');
require('dotenv').config();

const uri = process.env.MONGODB_URI;


mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.error('Failed to connect to MongoDB Atlas', err));

  const UserSchema = new mongoose.Schema({
    name: { 
      type: String, 
      required: [true, 'Name is required'], 
      trim: true, 
      minlength: [3, 'Name must be at least 3 characters long'], 
      maxlength: [50, 'Name cannot exceed 50 characters'] 
    },
    email: { 
      type: String, 
      required: [true, 'Email is required'], 
      unique: true, 
      trim: true, 
      lowercase: true,
      match: [/.+@.+\..+/, 'Please enter a valid email address'] 
    },
    password: { 
      type: String, 
      required: [true, 'Password is required'], 
      minlength: [8, 'Password must be at least 8 characters long'], 
      maxlength: [128, 'Password cannot exceed 128 characters']
    },
    role: { 
        type: String, 
        enum: ['user', 'admin'], 
        default: 'user' 
      },

      otp: { 
        type: String,
        trim: true,  
        minlength: [6, 'OTP must be minimum 6 characters'], 
        maxlength: [6, 'OTP must be maximum 6 characters'],
        default: '000000'
      },
      otpExpiresAt: { 
        type: Date 
      },
      emailVerified: { 
        type: Boolean, 
        default: false 
      },

    createdAt: { 
      type: Date, 
      default: Date.now 
    }
  });

  const User = mongoose.model('User', UserSchema);

  module.exports = {
    User
  };