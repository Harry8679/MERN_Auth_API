const express = require('express');
const { registerUser, loginUser, logoutUser, getUser, updateUser, deleteUser, getUsers } = require('../controllers/user.controller');
const { protect, adminOnly, authorOnly } = require('../middlewares/auth.middleware');
const userRouter = express.Router();

userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.get('/logout', logoutUser);
userRouter.get('/getUser', protect, getUser);
userRouter.patch('/updateUser', protect, updateUser);
userRouter.delete('/:id', protect, adminOnly, deleteUser);
userRouter.get('/getUsers', protect, authorOnly, getUsers);

module.exports = userRouter;