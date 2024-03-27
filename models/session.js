import { Schema, model } from 'mongoose';

const sessionSchema = new Schema(
  {
    members: {
      userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
      },
      consultantId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
      },
    },
    expireAt: {
      type: Date,
      default: Date.now,
      expires: 100,
    },
  },
  { timestamps: true }
);

export default model('Session', sessionSchema);
