import Product from '../models/product.js';
import fs from 'fs';

// Lay tat ca cac product
export const getProducts = async (req, res, next) => {
  try {
    const products = await Product.find();

    res.status(200).json(products);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Lay 8 products cho trang index
export const getProductsIndex = async (req, res, next) => {
  try {
    const products = await Product.find().limit(8);

    res.status(200).json(products);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Lay cac product co cung category
export const getRelatedProds = async (req, res, next) => {
  try {
    const { cate } = req.query;
    const products = await Product.find({ category: cate });
    res.status(200).json(products);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
// Lay product theo id
export const getProduct = async (req, res, next) => {
  const prodId = req.params.id;
  try {
    const product = await Product.findById(prodId);
    if (!product) {
      const err = new Error('No product found');
      err.statusCode = 404;
      throw err;
    }
    res.status(200).json(product);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Lay product theo trang va category
export const getProductByCate = async (req, res, next) => {
  const { cate, page } = req.query;
  const ITEMS_PER_PAGE = 9;
  try {
    let products = [];
    let totalProducts;
    if (cate === 'all') {
      products = await Product.find()
        .skip((+page - 1) * ITEMS_PER_PAGE)
        .limit(ITEMS_PER_PAGE);
      totalProducts = await Product.find().countDocuments();
    } else {
      products = await Product.find({ category: cate })
        .skip((+page - 1) * ITEMS_PER_PAGE)
        .limit(ITEMS_PER_PAGE);
      totalProducts = await Product.find({ category: cate }).countDocuments();
    }
    // products = []
    if (!products) {
      const err = new Error('No product found');
      err.statusCode = 404;
      throw err;
    }
    res.status(200).json({ products, totalProducts });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Create new product

export const addProduct = async (req, res, next) => {
  const productData = req.body;

  try {
    const newProduct = await Product.create(productData);
    res.status(201).json(newProduct);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

export const uploadImage = (req, res, next) => {
  const uploadedFiles = [];
  for (let i = 0; i < req.files.length; i++) {
    const { path, originalname } = req.files[i];
    const ext = originalname.split('.')[1];
    const newPath = path + '.' + ext;
    fs.renameSync(path, newPath);
    uploadedFiles.push(newPath.replace('images/', ''));
  }
  res.json(uploadedFiles);
};

// Update product
export const updateProduct = async (req, res, next) => {
  const prodId = req.params.id;

  try {
    const updatedProduct = await Product.findByIdAndUpdate(
      prodId,
      {
        $set: req.body,
      },
      { new: true }
    );
    res.status(200).json(updatedProduct);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Delete Product
export const deleteProduct = async (req, res, next) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.status(200).json('Deleted Product');
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
