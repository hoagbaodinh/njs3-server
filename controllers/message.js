import Message from '../models/message.js';

//Create new message
export const createMessage = async (req, res, next) => {
  const message = new Message(req.body);
  console.log(message);
  console.log(req.body);
  try {
    const savedMessage = await message.save();
    res.status(201).json(savedMessage);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Get message by sessionId

export const getMessage = async (req, res, next) => {
  try {
    const message = await Message.find({
      sessionId: req.params.sessionId,
    });
    res.status(200).json(message);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
