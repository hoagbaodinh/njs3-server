import express from 'express';
import { login, register } from '../controllers/auth.js';
import User from '../models/user.js';
import { body } from 'express-validator';

const router = express.Router();

router.post(
  '/register',
  [
    body('email')
      .isEmail()
      .withMessage('Please enter valid email')
      .custom((value, { req }) => {
        return User.findOne({ email: value }).then((userDoc) => {
          if (userDoc) {
            return Promise.reject('Email is already in use');
          }
        });
      })
      .normalizeEmail(),
    body('password').trim().isLength({ min: 8 }),
    body('fullname').trim().not().isEmpty(),
    body('phone').trim().not().isEmpty(),
  ],
  register
);
router.post(
  '/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').trim().isLength({ min: 8 }),
  ],
  login
);

export default router;
