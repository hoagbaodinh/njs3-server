import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import productRoutes from './routes/product.js';
import orderRoutes from './routes/order.js';
import userRoutes from './routes/user.js';
import sessionRoutes from './routes/session.js';
import messageRoutes from './routes/message.js';
import cartRoutes from './routes/cart.js';
import http from 'http';
import { Server } from 'socket.io';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import helmet from 'helmet';
import compression from 'compression';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();

dotenv.config();

const connect = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URL);
    console.log('Connected to MongoDB');
  } catch (err) {
    throw err;
  }
};
mongoose.connection.on('disconnected', () => {
  console.log('mongoDB disconnected');
});

app.use(cookieParser());
app.use(express.json());
app.use(
  cors({
    origin: [
      'http://localhost:3000',
      'http://localhost:3001',
      'https://njs-asm3-client-mtlz.onrender.com',
      'https://njs-asm3-admin-862k.onrender.com',
    ],
    credentials: true,
  })
);
app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);
app.use(compression());

app.use('/images', express.static(path.join(__dirname, 'images')));

app.use('/api/auth', authRoutes);
app.use('/api/products', productRoutes);
app.use('/api/order', orderRoutes);
app.use('/api/users', userRoutes);
app.use('/api/session', sessionRoutes);
app.use('/api/message', messageRoutes);
app.use('/api/cart', cartRoutes);
app.set('trust proxy', 1);

app.use('/', (req, res) => {
  console.log(req.cookies.access_token);
  res.send('Welcome');
});

app.use((error, req, res, next) => {
  console.log(error);
  const status = error.status || 500;
  const message = error.message;
  const data = error.data;
  res.status(status).json({ message, data });
});

// SOCKET.IO
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});
let users = [];

// const addUser = (userId, socketId) => {
//   !users.some((user) => user.userId === userId) &&
//     users.push({ userId, socketId });
// };
const addUser = (userId, socketId, role) => {
  !users.some((user) => user.userId === userId) &&
    users.push({ userId, socketId, role });
};

const removeUser = (socketId) => {
  users = users.filter((user) => user.socketId !== socketId);
};

const getUserFromClient = (userId) => {
  return users.find((user) => user.userId === userId);
};

io.on('connection', (socket) => {
  socket.on('addUser', (user) => {
    addUser(user.userId, socket.id, user.role);
    console.log(`User ${user.userId} connected`);

    io.emit('getUsers', users);
  });

  socket.on('sessionsChange', () => {
    io.emit('getSession', 'New session created');
  });

  // send and get message
  socket.on('sendMessage', ({ sessionId, receiverId, text, from }) => {
    if (from === 'consultant') {
      const user = getUserFromClient(receiverId);
      console.log(user);
      console.log(receiverId);
      user &&
        io.to(user?.socketId).emit('getMessage', {
          isConsultant: true,
          text,
        });
    } else {
      const consultant = users.filter((user) => user.role === 'consultant');
      consultant.map((u) => {
        io.to(u.socketId).emit('getMessage', {
          sessionId,
          isConsultant: false,
          text,
        });
      });
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected');
    removeUser(socket.id);
    io.emit('getUsers', users);
  });
});

server.listen(process.env.PORT || 5000, () => {
  connect();
});
