const express = require('express');
const zod = require('zod');
const { User } = require('../db');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
require('dotenv').config();

const registerBody = zod.object({
  name: zod.string().trim().min(3, { message: 'Name must be at least 3 characters long' }).max(50, { message: 'Name cannot exceed 50 characters' }).nonempty({ message: 'Name is required' }),

  email: zod.string().trim().email({ message: 'Please enter a valid email address' }).nonempty({ message: 'Email is required' }),

  password: zod.string().min(8, { message: 'Password must be at least 8 characters long' }).max(128, { message: 'Password cannot exceed 128 characters' }).nonempty({ message: 'Password is required' }),
  });

const loginBody = zod.object({

  email: zod.string().trim().email({ message: 'Please enter a valid email address' }).nonempty({ message: 'Email is required' }),

  password: zod.string().min(8, { message: 'Password must be at least 8 characters long' }).max(128, { message: 'Password cannot exceed 128 characters' }).nonempty({ message: 'Password is required' }),
  });

const resetPasswordRequestBody = zod.object({
    email: zod.string().trim().email({ message: 'Please enter a valid email address' }).nonempty({ message: 'Email is required' })
  })

const resetPasswordQuery = zod.object({
    token: zod.string().trim().nonempty({ message: 'Token is required' }),
  });

const resetPasswordBody = zod.object({
    password: zod.string().min(8, { message: 'Password must be at least 8 characters long' }).max(128, { message: 'Password cannot exceed 128 characters' }).nonempty({ message: 'Password is required' })
})
  



router.post('/register', async (req, res) => {
    try{
    const parsedBody = registerBody.safeParse(req.body);
    if (!parsedBody.success) {
      return res.status(400).json({ message: 'Incorrect input'});
    }
  
    const existingUser = await User.findOne({
      email: req.body.email,
    });
  
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

     const salt = await bcrypt.genSalt(10);
     hashedPassword = await bcrypt.hash(req.body.password, salt);
  
    await User.create({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    });
  
    return res.status(201).json({ message: 'User created successfully'});
} catch(err) {
    console.log(err)
    return res.status(500).json({ message: "Server error" });
}
  });

router.post('/login', async (req,res) => {
    try{
    const parsedBody = loginBody.safeParse(req.body);
    if (!parsedBody.success) {
        return res.status(400).json({ message: 'Incorrect input' });
      }
      const user = await User.findOne({
        email: req.body.email,
      });
    
      if (!user) {
        return res.status(401).json({ message: 'User not found'});
      }


      const isMatch = await bcrypt.compare(req.body.password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: "Incorrect password" });
      }

      const secret = process.env.JWT_SECRET;
      const token = jwt.sign({ userId: user._id }, secret);
    
      res.json({
        message: 'Login successful',
        token: token
      });
    }catch(err) {
        console.log(err)
        return res.status(500).json({ message: "Server error" });
    }
})

router.post('/reset-password-request', async (req, res) => {
    try{
    
    const parsedBody = resetPasswordRequestBody.safeParse(req.body);

    if (!parsedBody.success) {
        return res.status(400).json({ message: 'Incorrect input' });
      }
    const  email  = req.body.email;

    const user = await User.findOne({ email });

    if (!user) {
        return res.status(404).json({ message: "User doesn't exist" });
    }

    const secret = process.env.JWT_SECRET;
    const token = jwt.sign({ userId: user._id }, secret,{ expiresIn: '5m' });

     const resetURL = `http://localhost:3000/api/v1/auth/resetpassword?token=${token}`;

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASS
      },
    });

    const mailOptions = {
      to: user.email,
      from: process.env.EMAIL,
      subject: 'Password Reset Request',
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
      Please click on the following link, or paste this into your browser to complete the process:\n\n
      ${resetURL}\n\n
      If you did not request this, please ignore this email and your password will remain unchanged.\n`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: 'Password reset link sent' });
  } catch (error) {
    console.log(error)
    res.status(500).json({ message: 'Something went wrong' });
  }
  });


  router.post('/resetpassword', async (req, res) => {

  try {
    const parsedParams = resetPasswordQuery.safeParse(req.query);
    const parsedBody = resetPasswordBody.safeParse(req.body);


    if (!parsedBody.success || !parsedParams.success) {
        return res.status(400).json({ message: 'Incorrect input' });
      }
    const { token } = req.query;

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const id = decoded.userId;

    const user = await User.findOne({ _id: id });
    if (!user) {
      return res.status(400).json({ message: "User not exists!" });
    }

    const salt = await bcrypt.genSalt(10);
    hashedPassword = await bcrypt.hash(req.body.password, salt);
    await User.updateOne(
      {
        _id: id,
      },
      {
        $set: {
          password: hashedPassword,
        },
      }
    );


    await user.save();

    res.status(200).json({ message: 'Password has been reset' });
  } catch (error) {
    res.status(500).json({ message: 'Something went wrong' });
  }
  })


  module.exports = router;
