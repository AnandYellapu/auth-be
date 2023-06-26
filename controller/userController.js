const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../models/User');

const register = async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({ email, password: hashedPassword });
    res.status(201).json({ user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to register user' });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

    res.status(200).json({ user, token });
  } catch (error) {
    res.status(500).json({ error: 'Failed to login' });
  }
};

const getProfile = (req, res) => {
  res.status(200).json({ user: req.user });
};

// const forgotPassword = async (req, res) => {
//   const { email } = req.body;

//   try {
//     const user = await User.findOne({ email });

//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     // Generate and send the password reset link to the user's email
//     // Implement your logic to send the email here

//     res.status(200).json({ message: 'Password reset link sent successfully' });
//   } catch (error) {
//     res.status(500).json({ error: 'Failed to send reset password link' });
//   }
// };


// const resetPassword = async (req, res) => {
//   const { email } = req.body;

//   try {
//     const user = await User.findOne({ email });

//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     // Generate a reset token
//     const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

//     // Send the reset password link via email
//     const transporter = nodemailer.createTransport({
//       service: 'Your_Email_Service_Provider',
//       auth: {
//         user: process.env.EMAIL_USERNAME,
//         pass: process.env.EMAIL_PASSWORD,
//       },
//     });

//     const mailOptions = {
//       from: 'your_email@example.com',
//       to: email,
//       subject: 'Password Reset',
//       text: `Click the link below to reset your password: \n\n${process.env.CLIENT_URL}/reset-password/${token}`,
//     };

//     transporter.sendMail(mailOptions, (error, info) => {
//       if (error) {
//         console.log(error);
//         return res.status(500).json({ error: 'Failed to send reset password link' });
//       }
//       console.log('Reset password link sent:', info.response);
//       res.status(200).json({ message: 'Reset password link sent successfully' });
//     });
//   } catch (error) {
//     console.log(error);
//     res.status(500).json({ error: 'Failed to reset password' });
//   }
// };

const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate a reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    const resetPasswordExpires = Date.now() + 3600000; // Token expires in 1 hour

    // Store the reset token and expiration in the user document
    user.resetPasswordToken = resetPasswordToken;
    user.resetPasswordExpires = resetPasswordExpires;
    await user.save();

    // Send the reset password email
    sendPasswordResetEmail(user.email, resetToken);

    res.status(200).json({ message: 'Password reset email sent' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to process the request' });
  }
};


const resetPassword = async (req, res) => {
  const { token, password } = req.body;

  try {
    // Find the user with the matching reset token and check if it's not expired
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    // Update the user's password
    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
};


module.exports = { register, login, getProfile, forgotPassword, resetPassword };
