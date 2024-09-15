import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = 3002;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json());

const users = [
  { id: 1, username: 'admin', email: 'admin@example.com', password: 'hashed_password', role: 'admin', mustChangePassword: false }
];

const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (token == null) {
    console.log('No token provided');
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token verification failed:', err.message);
      return res.sendStatus(403);
    }

    req.user = user;
    next();
  });
};

const authorizeRole = (role) => (req, res, next) => {
  if (req.user.role !== role) return res.sendStatus(403);
  next();
};

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const existingUser = users.find(user => user.email === email);
  if (existingUser) return res.status(400).json({ error: 'Email уже зарегистрирован' });

  const newUser = {
    id: users.length + 1,
    username,
    email,
    password: hashedPassword,
    role: 'user',
    mustChangePassword: false,
  };

  users.push(newUser);
  res.status(201).json({ message: 'Пользователь зарегистрирован!' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(user => user.email === email);
  if (!user) return res.status(400).json({ error: 'Неверный email или пароль' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Неверный email или пароль' });

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.post('/update-email', authenticateJWT, (req, res) => {
  const { newEmail } = req.body;
  const user = users.find(user => user.id === req.user.id);

  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

  user.email = newEmail;
  res.json({ message: 'Email успешно обновлен', user });
});

app.post('/delete-account', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  const userIndex = users.findIndex(user => user.id === userId);

  if (userIndex === -1) return res.status(404).json({ error: 'Пользователь не найден' });

  users.splice(userIndex, 1);
  res.json({ message: 'Аккаунт успешно удален' });
});

app.post('/update-role', authenticateJWT, authorizeRole('admin'), (req, res) => {
  const { userId, newRole } = req.body;
  const user = users.find(user => user.id === userId);

  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

  user.role = newRole;
  res.json({ message: 'Роль успешно обновлена', user });
});

app.post('/refresh-token', authenticateJWT, (req, res) => {
  const token = jwt.sign({ id: req.user.id, role: req.user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
