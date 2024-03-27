import express from 'express';
import {
  createOrder,
  getAllOrders,
  getNumberOfOrder,
  getOrder,
  getOrderByUserId,
  getTotalEarning,
} from '../controllers/order.js';
import { verifyAdmin, verifyUser } from '../middlewares/verifyToken.js';

// import { body } from 'express-validator';

const router = express.Router();

// User
router.post('/create', verifyUser, createOrder);
router.get('/user/:userId', verifyUser, getOrderByUserId);
router.get('/order/:orderId', verifyUser, getOrder);

// Admin
router.get('/all-orders', verifyAdmin, getAllOrders);
router.get('/num-of-orders', verifyAdmin, getNumberOfOrder);
router.get('/total-earning', verifyAdmin, getTotalEarning);

export default router;
