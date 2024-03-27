import Session from '../models/session.js';
import Message from '../models/message.js';
import mongoose from 'mongoose';

// Tao 1 session moi
export const createSession = async (req, res, next) => {
  // Neu khong co userId thi khoi tao 1 userId mac dinh cho guest
  const userId = req.body.userId || new mongoose.Types.ObjectId();
  const newSession = new Session({
    members: {
      userId,
      consultantId: req.body.consultantId || '65ef0887b682885d88cb3ec7',
    },
  });

  try {
    const savedSession = await newSession.save();

    res.status(201).json(savedSession);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
// Lay tat ca Session hien co
export const getAllSession = async (req, res, next) => {
  try {
    const sessions = await Session.find();
    const reverseSessions = sessions.reverse();
    res.status(200).json(reverseSessions);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Lay session thong qua userId

export const getSessionByUserId = async (req, res, next) => {
  try {
    const session = await Session.findOne({
      'members.userId': req.params.userId || '',
    });
    res.status(200).json(session);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

export const getSessionById = async (req, res, next) => {
  try {
    const session = await Session.findById(req.params.id);
    res.status(200).json(session);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
// Update session userId
export const updateSession = async (req, res, next) => {
  try {
    const session = await Session.findById(req.params.id);
    if (!session) {
      const err = new Error('Session not found');
      err.statusCode = 404;
      throw err;
    }
    console.log(session);
    session.members.userId = req.body.userId;
    const newSession = await session.save();
    await Message.updateMany(
      { sessionId: req.params.id },
      { $set: { sender: req.body.userId } }
    );

    res.status(200).json(newSession);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

//Xoa session

export const deleteSession = async (req, res, next) => {
  try {
    const sessionId = req.params.sessionId;

    await Session.findByIdAndDelete(sessionId);
    await Message.deleteMany({ sessionId: sessionId });

    res.status(200).json('Successfully Delete Session');
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
