import { validationResult } from 'express-validator';
import bcrypt from 'bcryptjs';
import User from '../models/user.js';
import jwt from 'jsonwebtoken';

export const register = async function (req, res, next) {
  const { fullname, email, password, phone, isConsultant, isAdmin } = req.body;

  try {
    const errors = validationResult(req);
    // Kiem tra loi input
    if (!errors.isEmpty()) {
      const error = new Error('Validation failed');
      error.statusCode = 422;
      error.data = errors.array();
      throw error;
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
    // Kiem tra input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const error = new Error('Validation failed');
      error.statusCode = 422;
      error.data = errors.array();
      throw error;
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

    res
      .cookie('access_token', token)
      .status(200)
      .json({ userDetails: orderDetails });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
