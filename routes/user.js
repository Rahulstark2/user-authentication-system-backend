const express = require('express');
const { User } = require('../db');
const router = express.Router();
const { authMiddleware } = require('../middleware') 
const zod = require('zod');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const changeNameBody = zod.object({
  name: zod.string().trim().min(3, { message: 'Name must be at least 3 characters long' }).max(50, { message: 'Name cannot exceed 50 characters' }).nonempty({ message: 'Name is required' })
  });


const changePasswordBody = zod.object({
    currentPassword: zod.string().min(8, { message: 'Password must be at least 8 characters long' }).max(128, { message: 'Password cannot exceed 128 characters' }).nonempty({ message: 'Password is required' }),
    newPassword: zod.string().min(8, { message: 'Password must be at least 8 characters long' }).max(128, { message: 'Password cannot exceed 128 characters' }).nonempty({ message: ' New Password is required' })
  }).refine(data => data.newPassword !== data.currentPassword, {
    message: "New password must be different from current password",
    path: ["newPassword"]
  })

  const deleteAccountBody = zod.object({
    password: zod.string().min(8, { message: 'Password must be at least 8 characters long' }).max(128, { message: 'Password cannot exceed 128 characters' }).nonempty({ message: 'Password is required' })
  });

  const verifyEmailBody = zod.object({
      email: zod.string().trim().email({ message: 'Please enter a valid email address' }).nonempty({ message: 'Email is required' })
    })

   const verifyOtpBody = zod.object({
    email: zod.string().trim().email({ message: 'Please enter a valid email address' }).nonempty({ message: 'Email is required' }),
     otp: zod.string().trim().min(6, { message: 'OTP must be minimum 6 characters' }).max(6, { message: 'OTP must be maximum 6 characters' }).nonempty({ message: 'OTP is required' })
   })

router.get('/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password'); 

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({  message: 'Profile retrieved successfully', profile: user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

router.put('/change-name', authMiddleware, async (req, res) => {
    try {

        const parsedBody = changeNameBody.safeParse(req.body);
        if (!parsedBody.success) {
            return res.status(400).json({ message: 'Incorrect input'});
         }
        const  name  = req.body.name;

        if (!name) {
            return res.status(400).json({ message: 'Name is required' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.userId,{ name }, { new: true, runValidators: true }).select('-password');

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ message: 'Name updated successfully', profile: updatedUser });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

router.post('/change-password', authMiddleware, async (req, res) => {
    try {
        const parsedBody = changePasswordBody.safeParse(req.body);
        if (!parsedBody.success) {
            return res.status(400).json({ message: 'Incorrect input' });
        }

        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();

        res.status(200).json({ message: 'Password updated successfully'});
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

router.delete('/delete-account', authMiddleware, async (req, res) => {
    try {
        const parsedBody = deleteAccountBody.safeParse(req.body);
        if (!parsedBody.success) {
            return res.status(400).json({ message: 'Incorrect input' });
        }

        const { password } = req.body;
        const user = await User.findById(req.userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        await User.findByIdAndDelete(req.userId);
        res.status(200).json({ message: 'Account deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

router.post('/verify-email', async (req, res) => {
    try {
        const parsedBody = verifyEmailBody.safeParse(req.body);
        if (!parsedBody.success) {
            return res.status(400).json({ message: 'Incorrect input'});
         }
      const { email } = req.body;
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      if(user.emailVerified===true){
        return res.status(404).json({ message: 'Email already verified' });
      }
      const otp = crypto.randomInt(100000, 999999).toString();
  

      user.otp = otp;
      user.otpExpiresAt = Date.now() + 10 * 60 * 1000; 
      await user.save();
  

      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL, 
          pass: process.env.EMAIL_PASS
        }
      });
  
      const mailOptions = {
        from: process.env.EMAIL,
        to: user.email,
        subject: 'Email Verification Code',
        text: `Your OTP for email verification is ${otp}. This code will expire in 10 minutes.`
      };
  
      await transporter.sendMail(mailOptions);
  
      res.status(200).json({ message: 'OTP sent to email' });
    } catch (error) {
      console.log(error)
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.post('/verify-otp', async (req, res) => {
    try {
        const parsedBody = verifyOtpBody.safeParse(req.body);
        if (!parsedBody.success) {
            return res.status(400).json({ message: 'Incorrect input'});
         }
      const { email, otp } = req.body;
  
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      if (user.otp !== otp) {
        return res.status(400).json({ message: 'Invalid OTP' });
      }
  
      if (user.otpExpiresAt < Date.now()) {
        return res.status(400).json({ message: 'OTP expired' });
      }
  
      user.emailVerified = true;
      user.otp = '000000';
      user.otpExpiresAt = undefined;
      await user.save();
  
      res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
      console.log(error)
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.post('/logout', authMiddleware, (req, res) => {
    res.status(200).json({ message: 'Logged out successfully' });
});


module.exports = router;