const express = require('express');
const { registerUser, loginUser, logoutUser, getUser, updateUser, deleteUser } = require('../controllers/user.controller');
const { protect, adminOnly } = require('../middlewares/auth.middleware');
const userRouter = express.Router();

userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.get('/logout', logoutUser);
userRouter.get('/getUser', protect, getUser);
userRouter.patch('/updateUser', protect, updateUser);
userRouter.delete('/:id', protect, adminOnly, deleteUser);

module.exports = userRouter;