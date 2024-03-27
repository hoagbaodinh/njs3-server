import express from 'express';
import {
  createSession,
  deleteSession,
  getAllSession,
  getSessionById,
  getSessionByUserId,
  updateSession,
} from '../controllers/session.js';

// import { body } from 'express-validator';

const router = express.Router();

router.post('/create', createSession);
router.get('/session/:userId', getSessionByUserId);
router.get('/get-session/:id', getSessionById);
router.put('/update-session/:id', updateSession);
router.get('/all-sessions', getAllSession);
router.delete('/:sessionId', deleteSession);

export default router;
