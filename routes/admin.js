const express = require('express');
const { User } = require('../db');
const router = express.Router();
const { authMiddleware } = require('../middleware') 
const zod = require('zod');

const deleteUserBody = zod.object({
    email: zod.string().trim().email({ message: 'Please enter a valid email address' }).nonempty({ message: 'Email is required' })
  })


router.get('/users', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);

        if (!user) {
            return res.status(404).json({ message: 'Admin not found' });
        }

        if(user.role!="admin") {
            return res.status(404).json({ message: 'Admin access required' });
        }
        const users = await User.find().select('-password');
        res.status(200).json({ message: 'Users retrieved successfully',count: users.length, users });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});


router.delete('/user/:email', authMiddleware, async (req, res) => {
    try {
        const parsedBody = deleteUserBody.safeParse(req.params);
        if (!parsedBody.success) {
            return res.status(400).json({ message: 'Incorrect input'});
         }
        const user = await User.findById(req.userId);

        if (!user) {
            return res.status(404).json({ message: 'Admin not found' });
        }

        if(user.role!="admin") {
            return res.status(404).json({ message: 'Admin access required' });
        }

        
        const email = req.params.email.trim().toLowerCase();
        
        if (user.email === email) {
            return res.status(400).json({ message: 'Cannot delete own admin account' });
        }

        
        const deletedUser = await User.findOneAndDelete({ email });
        if (!deletedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ message: 'User deleted successfully',
            deletedUser: {
                id: deletedUser._id,
                email: deletedUser.email,
                role: deletedUser.role
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});
module.exports = router;