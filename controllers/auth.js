import bcrypt from 'bcryptjs';
import User from '../models/user.js';
import jwt from 'jsonwebtoken';

export const register = async function (req, res, next) {
  const { fullname, email, password, phone, isConsultant, isAdmin } = req.body;

  try {
    if (!fullname || !email || !password || !phone) {
      const err = new Error('You must provide all required fields');
      err.statusCode = 422;
      throw err;
    }
    const checkEmail = await User.findOne({ email: email });
    if (checkEmail) {
      const err = new Error('Email already in use');
      err.statusCode = 422;
      throw err;
    }
    if (password.length < 8) {
      const err = new Error('Password must be at least 8 characters');
      err.statusCode = 422;
      throw err;
    }

    // Ma hoa password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Tao user
    const user = new User({
      fullname,
      email,
      password: hashedPassword,
      phone,
      isConsultant: !!isConsultant,
      isAdmin: !!isAdmin,
    });
    // Luu user vao database
    await user.save();

    return res.status(201).json({ message: 'Register successfully', user });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

export const login = async function (req, res, next) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      const err = new Error('You must provide all required fields');
      err.statusCode = 422;
      throw err;
    }

    // Tim user thong qua email
    const user = await User.findOne({ email: email });
    // Bao loi neu khong tim thay user
    if (!user) {
      const error = new Error('Email not found');
      error.statusCode = 401;
      throw error;
    }

    // So sanh password
    const isEqual = await bcrypt.compare(password, user.password);
    // Bao loi neu password sai
    if (!isEqual) {
      const error = new Error('Password not correct');
      error.statusCode = 401;
      throw error;
    }
    // dang ki thong tin token
    const token = jwt.sign(
      {
        userId: user._id.toString(),
        fullname: user.fullname,
      },
      process.env.JWT_SECRET
    );
    //Bo password khoi du lieu gui ve client
    const { password: pass, ...orderDetails } = user._doc;
    console.log(token);
    res
      .cookie('access_token', token, {
        secure: true,
        httpOnly: true,
        sameSite: 'none',
      })
      .status(200)
      .json({ userDetails: orderDetails });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
