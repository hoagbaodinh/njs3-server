import jwt from 'jsonwebtoken';

export const verifyToken = (req, res, next) => {
  const token = req.cookies.access_token;
  if (!token) {
    const error = new Error('Not authenticated');
    error.status = 401;
    return next(error);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      const error = new Error('Token is not valid');
      error.status = 403;
      return next(error);
    }
    req.user = user;
    next();
  });
};

// Check user
export const verifyUser = (req, res, next) => {
  verifyToken(req, res, next, () => {
    // Neu khong ton tai user
    if (!req.user) {
      const error = new Error('You are not authorized');
      error.status = 403;
      return next(error);
    }
    next();
  });
};

//Check Admin
export const verifyAdmin = (req, res, next) => {
  verifyToken(req, res, next, () => {
    // Neu user khong phai admin
    if (!req.user?.isAdmin) {
      const error = new Error('You are not authorized');
      error.status = 403;
      return next(error);
    }
    next();
  });
};
