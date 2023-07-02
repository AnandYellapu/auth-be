const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
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
//   const token = await crypto.randomBytes(20).toString("hex");
//   const user = await User.findOne({ email: req.body.email });

//   if (!user) {
//     return res.status(400).json({ error: "No user with such email!" });
//   }

//   user.resetPasswordToken = token;
//   user.resetPasswordExpires = Date.now() + 3600000;

//   try {
//     await user.save();

//     let transporter = nodemailer.createTransport({
//       host: "smtp.ethereal.email",
//       service: "gmail",
//       port: 465,
//       secure: true,
//       auth: {
//         user: "anandsaiii1200@gmail.com",
//         pass: "azjtjuhdytbpdcfn",
//       },
//     });

//     let info = await transporter.sendMail({
//       from: `anandsaiii1200@gmail.com`,
//       to: user.email,
//       subject: "AUTH - Reset Password",
//       text: `You are receiving this because you have requested the reset of the password of your account.\n\nToken: ${token}\n\nIf you didn't request this, please ignore this email and your password will remain unchanged.`,
//       html: `<p>You are receiving this because you have requested the reset of the password of your account.</p><p><strong>Token: ${token}</strong></p><p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>`,
//     });

//     return res.json({
//       message: `An email has been sent to ${user.email} with further instructions`,
//     });
//   } catch (error) {
//     return res.status(400).json({ error: error.message });
//   }
// };

const forgotPassword = async (req, res) => {
  try {
    const token = crypto.randomBytes(20).toString('hex');
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(400).json({ error: 'No user with such email!' });
    }

    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000;

    await user.save();

    const transporter = nodemailer.createTransport({
      // Configure your email service provider settings
      service: 'gmail',
      auth: {
        user: 'anandsaiii1200@gmail.com',
        pass: 'azjtjuhdytbpdcfn',
      },
    });

    const mailOptions = {
      from: 'anandsaiii1200@gmail.com',
      to: user.email,
      subject: 'Password Reset',
      text:
        'You are receiving this email because you requested a password reset. Please click on the following link to reset your password:',
      html: `<a href="http://localhost:5000/api/users/reset-password/:token/${token}">Reset Password</a>`,
    };

    await transporter.sendMail(mailOptions);

    res.json({
      message: 'An email has been sent with further instructions.',
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Internal server error' });
  }
};


const resetPassword = async (req, res) => {
  const { token, password } = req.body;

  try {
    // Find the user with the reset token and check the expiration
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update the user's password and reset token fields
    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
};

module.exports = { register, login, forgotPassword, resetPassword, getProfile };
