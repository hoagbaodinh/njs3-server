import User from '../models/user.js';
import Cart from '../models/cart.js';
import Session from '../models/session.js';

export const getNumOfUsers = async (req, res, next) => {
  try {
    const numOfUser = await User.countDocuments();
    res.status(200).json(numOfUser);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

export const getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);

    res.status(200).json(user);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

export const updateUser = async (req, res, next) => {
  const { isConsultant, isAdmin, ...other } = req.body;

  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          ...other,
          isConsultant: !!isConsultant,
          isAdmin: !!isAdmin,
        },
      },
      { new: true }
    );
    res.status(200).json(user);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

export const getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find();
    res.status(200).json(users);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

export const deleteUser = async (req, res, next) => {
  try {
    await User.findByIdAndDelete(req.params.id);

    await Cart.findOneAndDelete({ userId: req.params.id });

    await Session.findOneAndDelete({ 'members.userId': req.params.id });
    console.log('done!');
    res.status(200).json('User deleted successfully');
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
