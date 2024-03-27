import express from 'express';
import {
  getNumOfUsers,
  getUser,
  updateUser,
  getAllUsers,
  deleteUser,
} from '../controllers/user.js';
import { verifyAdmin } from '../middlewares/verifyToken.js';

const router = express.Router();

router.get('/num-of-users', verifyAdmin, getNumOfUsers);
router.get('/get-user/:id', verifyAdmin, getUser);
router.get('/all-users', verifyAdmin, getAllUsers);
router.put('/edit-user/:id', verifyAdmin, updateUser);
router.delete('/:id', verifyAdmin, deleteUser);
export default router;
