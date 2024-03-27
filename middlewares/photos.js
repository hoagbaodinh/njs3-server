import multer from 'multer';

const photosMiddleware = multer({ dest: 'images/' });

export default photosMiddleware;
