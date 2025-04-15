import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import {hash, compare} from './scrypt.js'; // renamed from scrypt.js
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { verrifyToken } from './middleware/session.js'; // renamed from sessionMiddleware

dotenv.config();

const app = express();
const port = process.env.PORT || 1080;

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MySQL
const db = await mysql.createConnection({
  user: process.env.USER,
  host: process.env.HOST,
  database: process.env.DATABASE,
  password: process.env.PASSWORD,
  port: 3306,
});

try {
  await db.connect();
  console.log("Connected to the database");
} catch (err) {
  console.error("Database connection error:", err);
}

// Signup Route
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  try {
    const [result] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
    if (result.length > 0) return res.status(400).send("Username already exists");

    const hashedPassword = await hash(password, 10);
    await db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword]);
    res.status(200).send("User created successfully");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error creating user");
  }
});

// Signin Route (returns JWT)
app.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  try {
    const [result] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
    if (result.length === 0) return res.status(400).send("User not found");

    const user = result[0];
    const isMatch = await compare(password, user.password);

    if (!isMatch) return res.status(400).send("Invalid password");

    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return res.status(200).json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).send("Error logging in");
  }
});

// Protected Routes Using JWT Middleware
app.post("/packing", verrifyToken, async (req, res) => {
  const { itemName, boxNumber } = req.body;
  if (!itemName || !boxNumber) return res.status(400).send("Missing item name or box number");

  try {
    await db.query("INSERT INTO itemList (itemName, boxNumber) VALUES (?, ?)", [itemName, boxNumber]);
    res.status(200).send("Item added successfully");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error adding item");
  }
});

app.post("/unpack", verrifyToken, async (req, res) => {
  const { boxNumber } = req.body;
  if (!boxNumber) return res.status(400).send("Missing box number");

  try {
    const [result] = await db.query("SELECT * FROM itemList WHERE boxNumber = ? ORDER BY itemName", [boxNumber]);
    result.length > 0 ? res.status(200).send(result) : res.status(404).send("No items found");
  } catch (err) {
    console.error("Error retrieving items:", err);
    res.status(500).send("Error retrieving items");
  }
});

app.post("/item", verrifyToken, async (req, res) => {
  const { itemName } = req.body;
  if (!itemName) return res.status(400).send("Missing item name");

  try {
    const [result] = await db.query("SELECT * FROM itemList WHERE itemName LIKE ? ORDER BY itemName", [`%${itemName}%`]);
    result.length > 0 ? res.status(200).send(result) : res.status(404).send("Item not found");
  } catch (err) {
    console.error("Error retrieving item:", err);
    res.status(500).send("Error retrieving item");
  }
});

// Dummy Logout (handled on client)
app.post("/logout", (req, res) => {
  // No server-side action needed for JWT logout
  res.status(200).send("Client should delete token to logout");
});

// Start Server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
