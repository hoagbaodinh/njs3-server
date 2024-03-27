import { Schema, model } from 'mongoose';

const messageSchema = new Schema(
  {
    sessionId: {
      type: Schema.Types.ObjectId,
      ref: 'Session',
      required: true,
    },
    isConsultant: {
      type: Boolean,
    },
    text: {
      type: String,
    },
  },
  { timestamps: true }
);

export default model('Message', messageSchema);
