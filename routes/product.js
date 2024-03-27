import express from 'express';
import {
  addProduct,
  deleteProduct,
  getProduct,
  getProducts,
  getProductsIndex,
  getRelatedProds,
  updateProduct,
  uploadImage,
  getProductByCate,
} from '../controllers/product.js';
import photosMiddleware from '../middlewares/photos.js';
import { verifyAdmin } from '../middlewares/verifyToken.js';

const router = express.Router();

// Client routes
router.get('/all-products', getProducts);
router.get('/products-index', getProductsIndex);
router.get('/related', getRelatedProds);
router.get('/get-product/:id', getProduct);
router.get('/get-products-by-cate', getProductByCate);

// Admin
router.post('/add-product', verifyAdmin, addProduct);
router.post(
  '/upload-image',
  photosMiddleware.array('photos', 100),
  verifyAdmin,
  uploadImage
);
router.put('/edit-product/:id', verifyAdmin, updateProduct);
router.delete('/:id', verifyAdmin, deleteProduct);

export default router;
