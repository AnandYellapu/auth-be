const express = require('express');
const router = express.Router();
const UserController = require('../controller/UserController');
const authenticateToken = require('../middleware/authenticateToken');


router.post('/register', UserController.register);
router.post('/login', UserController.login);
router.post('/forgot-password', UserController.forgotPassword);
router.post('/reset-password', UserController.resetPassword);
router.get('/profile', authenticateToken, UserController.getProfile);


module.exports = router;
