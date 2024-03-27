import Cart from '../models/cart.js';

// Tim Cart
export const getCart = async (req, res, next) => {
  try {
    const cart = await Cart.findOne({ userId: req.params.userId }).populate(
      'items.productId'
    );

    if (cart) {
      const items = cart.items.map((item) => ({
        _id: item.productId._id,
        price: item.productId.price,
        quantity: item.quantity,
        title: item.productId.name,
        totalPrice: item.quantity * item.productId.price,
        image: item.productId.img1,
        stock: item.productId.stock,
      }));
      const filterItems = items
        .map((item) =>
          item.quantity > item.stock ? { ...item, quantity: item.stock } : item
        )
        .filter((item) => item.quantity !== 0);
      return res.status(200).json(filterItems);
    } else {
      const newCart = await Cart.create({
        userId: req.params.userId,
        items: [],
      });
      return res.status(201).json(newCart.items);
    }
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Them 1 item vao cart
export const addToCart = async (req, res, next) => {
  const { userId, productId, quantity } = req.body;

  try {
    // Tim xem user da co cart hay chua
    const cart = await Cart.findOne({ userId: userId });
    console.log(cart);
    // Chua co cart
    if (!cart) {
      // Tao cart moi
      const newCart = await Cart.create({ userId: userId });
      // Them item vao cart
      newCart.items.push({ productId, quantity });
      await newCart.save();
      return res.status(201).json('Item has been added to cart');
    }

    // Kiem tra cart da co item hay chua
    if (cart.items.length === 0) {
      cart.items.push({ productId, quantity });
      await cart.save();
      return res.status(201).json('Item has been added to cart');
    }

    // Tim index cua item trong cart
    const itemIndex = cart.items.findIndex(
      (item) => item.productId.toString() === productId.toString()
    );

    // Khong tim thay item
    if (itemIndex === -1) {
      cart.items.push({ productId, quantity });
      await cart.save();
      return res.status(201).json('Item has been added to cart');
    }

    cart.items[itemIndex].quantity += quantity;
    await cart.save();

    return res.status(200).json('Item has been added to cart');
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Xoa 1 item ra khoi cart

export const removeOneItemFromCart = async (req, res, next) => {
  const { userId, productId } = req.body;

  try {
    // Tim cart
    const cart = await Cart.findOne({ userId: userId });
    console.log(cart.items[0]);
    // Tim item index
    const itemIndex = cart.items.findIndex(
      (item) => item.productId.toString() === productId
    );

    console.log(itemIndex);
    cart.items[itemIndex].quantity -= 1;

    // Neu quantity cua item do = 0 thi xoa item ra khoi cart
    if (cart.items[itemIndex].quantity === 0) {
      cart.items = cart.items.filter(
        (item) => item.productId.toString() !== productId
      );
    }

    await cart.save();
    return res.status(200).json('Item has been remove from cart');
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Xoa item ra khoi cart

export const deleteItemFromCart = async (req, res, next) => {
  const { userId, productId } = req.body;
  try {
    // Tim cart
    const cart = await Cart.findOne({ userId: userId });
    // Xoa item ra khoi cart
    cart.items = cart.items.filter(
      (item) => item.productId.toString() !== productId
    );
    console.log(cart);

    await cart.save();
    return res.status(200).json('Item has been remove from cart');
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Xoa cart

export const deleteCart = async (req, res, next) => {
  const { userId } = req.body;
  try {
    // Tim cart
    await Cart.findByIdAndDelete({ userId: userId });

    return res.status(200).json('Cart has been deleted');
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Thay the cart

export const replaceCart = async (req, res, next) => {
  const { userId, items } = req.body;

  const cartItems = items.map((item) => ({
    productId: item._id,
    quantity: item.quantity,
  }));

  try {
    // Tim cart theo userID
    const cart = await Cart.findOne({ userId: userId });
    if (!cart) {
      // Tao moi neu khong co cart
      await Cart.create({ userId: userId, items: cartItems });
    } else {
      // update cart
      cart.items = cartItems;
      await cart.save();
    }
    res.status(200).json('Successfully replace cart');
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};
