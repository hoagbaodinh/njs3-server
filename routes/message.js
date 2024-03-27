import express from 'express';
import { createMessage, getMessage } from '../controllers/message.js';

// import { body } from 'express-validator';

const router = express.Router();

router.post('/create', createMessage);
router.get('/:sessionId', getMessage);

export default router;
