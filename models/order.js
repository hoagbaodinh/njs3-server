import { Schema, model } from 'mongoose';

const orderSchema = new Schema(
  {
    products: [
      {
        prodId: {
          type: Schema.Types.ObjectId,
          ref: 'Product',
        },
        quantity: {
          type: Number,
          required: true,
        },
      },
    ],
    fullname: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    phone: {
      type: String,
      required: true,
    },
    address: {
      type: String,
      required: true,
    },
    total_price: {
      type: Number,
      required: true,
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'user',
      required: true,
    },
    delivery: {
      type: String,
      default: 'Waiting for processing',
    },
    status: {
      type: String,
      default: 'Waiting for payment',
    },
  },
  { timestamps: true }
);

export default model('Order', orderSchema);
