import express from 'express';
import {
  addToCart,
  deleteCart,
  deleteItemFromCart,
  getCart,
  removeOneItemFromCart,
  replaceCart,
} from '../controllers/cart.js';
import { verifyUser } from '../middlewares/verifyToken.js';

const router = express.Router();

router.get('/get-cart/:userId', verifyUser, getCart);
router.post('/add-item', verifyUser, addToCart);
router.post('/replace-cart', verifyUser, replaceCart);
router.put('/remove-item', verifyUser, removeOneItemFromCart);
router.put('/delete-item', verifyUser, deleteItemFromCart);
router.delete('/delete-cart', verifyUser, deleteCart);

export default router;
