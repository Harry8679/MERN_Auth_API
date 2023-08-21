const express = require('express');
const { registerUser, loginUser, logoutUser, getUser, updateUser, deleteUser, getUsers, loginStatus, upgradeUser } = require('../controllers/user.controller');
const { protect, adminOnly, authorOnly } = require('../middlewares/auth.middleware');
const userRouter = express.Router();

userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.get('/logout', logoutUser);
userRouter.get('/getUser', protect, getUser);
userRouter.patch('/updateUser', protect, updateUser);
userRouter.delete('/:id', protect, adminOnly, deleteUser);
userRouter.get('/getUsers', protect, authorOnly, getUsers);
userRouter.get('/loginStatus', loginStatus);
userRouter.get('/upgradeUser', protect, adminOnly, upgradeUser);

module.exports = userRouter;