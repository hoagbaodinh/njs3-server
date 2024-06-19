import Order from '../models/order.js';
import Cart from '../models/cart.js';
import Product from '../models/product.js';
import nodemailer from 'nodemailer';
import sendGridTransport from 'nodemailer-sendgrid-transport';
import formatPrice from '../util/format-price.js';

const transporter = nodemailer.createTransport(
  sendGridTransport({
    auth: {
      api_key: process.env.SEND_GRID_API,
    },
  })
);
// Tao order moi
export const createOrder = async (req, res, next) => {
  try {
    const { userId, fullname, email, phone, address, items, totalPrice } =
      req.body;
    const order = new Order({
      fullname,
      email,
      phone,
      address,
      total_price: totalPrice,
      products: items.map((item) => {
        return {
          prodId: item._id,
          quantity: item.quantity,
        };
      }),
      userId,
    });
    await order.save();

    await Cart.findOneAndDelete({ userId: userId });
    // Gwi res cho user da tao order thanh cong
    res.status(201).json({ message: 'Order created successfully!' });
    // Xoa cart cua user

    // Cap nhat stock cua product
    items.map(async (item) => {
      const product = await Product.findById(item._id);
      product.stock -= item.quantity;
      await product.save();
    });

    // Send Mail

    // Table products
    const tableRow = items
      .map((item) => {
        return `
      <tr style="font-size:24px; text-align:center">
        <td style="border: 1px solid">${item.title}</td>
        <td style="border: 1px solid"><img src=${
          item.image
        } alt="" style="width:100px"/></td>
        <td style="border: 1px solid">${formatPrice(item.price)}</td>
        <td style="border: 1px solid">${item.quantity}</td>
        <td style="border: 1px solid">${formatPrice(item.totalPrice)}</td>
      </tr>
      `;
      })
      .join('\n');
    return transporter.sendMail({
      to: email,
      from: 'hoagbao.dinh@gmail.com',
      subject: 'Order Information',
      html: `
      <div style="background-color: black; color:white!important; padding: 10px 20px">
        <h1 style="color:white">Xin chào ${fullname}</h1>
        <h4 style="color:white">Phone: ${phone}</h4>
        <h4>Address: ${address}</h4>
        <table style="width:100%; border: 1px solid ;color:white">
          <tr>
            <th style="border: 1px solid">Tên Sản Phẩm</th>
            <th style="border: 1px solid">Hình Ảnh</th>
            <th style="border: 1px solid">Giá</th>
            <th style="border: 1px solid">Số lượng</th>
            <th style="border: 1px solid">Thành tiền</th>
          </tr>
          ${tableRow}
        </table>
        <h1>Tổng Thanh Toán:</h1>
        <h1>${formatPrice(totalPrice)}</h1>
        <br>
        <h1>Cảm ơn bạn!</h1>
      </div>
      `,
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
// Lay du lieu order qua userId
export const getOrderByUserId = async (req, res, next) => {
  try {
    const userId = req.params.userId;
    if (!userId) {
      const err = new Error('No user provided');
      err.statusCode = 404;
      throw err;
    }
    const orders = await Order.find({ userId: userId });
    return res.status(200).json(orders || []);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Lay du lieu order qua orderId
export const getOrder = async (req, res, next) => {
  try {
    const orderId = req.params.orderId;
    if (!orderId) {
      const err = new Error('No order provided');
      err.statusCode = 404;
      throw err;
    }
    const order = await Order.findById(orderId).populate({
      path: 'products',
      populate: {
        path: 'prodId',
      },
    });
    return res.status(200).json(order);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Lay du lieu tat ca order
export const getAllOrders = async (req, res, next) => {
  try {
    const orders = await Order.find();

    res.status(200).json(orders);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Lay du lieu gia tri cua tat ca cac order
export const getTotalEarning = async (req, res, next) => {
  try {
    const orders = await Order.find();
    const totalEaring = orders.reduce((acc, cur) => cur.total_price + acc, 0);
    res.status(200).json(totalEaring);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Lay du lieu cua so luong order
export const getNumberOfOrder = async (req, res, next) => {
  try {
    const orders = await Order.countDocuments();

    res.status(200).json(orders);
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
