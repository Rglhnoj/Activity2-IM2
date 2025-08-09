const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/auth-model");

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret"; // Use env variable in production
const JWT_EXPIRES_IN = "1d"; // Token valid for 1 day

const register = async (req, res) => {
  const { name, email, password } = req.body;

  let errors = [];

  if (!name) errors.push({ field: "name", message: "Name is required." });
  if (!email) errors.push({ field: "email", message: "Email is required." });
  if (!password)
    errors.push({ field: "password", message: "Password is required." });

  if (errors.length > 0) return res.status(400).json(errors);

  try {
    const emailExists = await User.emailExists(email);
    if (emailExists)
      return res.status(400).json({ message: "Email already registered" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await User.createUser(name, email, hashedPassword);

    res.status(201).json({
      message: "User has been created successfully.",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "Email and password are required" });

  try {
    const user = await User.findByEmail(email); // You must have this method in your model
    if (!user)
      return res.status(401).json({ message: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Send token in HttpOnly cookie
    res
      .cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production", // true in production
        maxAge: 24 * 60 * 60 * 1000, // 1 day
        sameSite: "Strict",
      })
      .status(200)
      .json({ message: "Login successful" });
  } catch (error) { 
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};

module.exports = {
  register,
  login,
};
