const express = require('express');
const winston = require('winston');

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

logger.info('Application started');

const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');

const app = express();
app.use(express.json());
app.use(helmet());

const users = [];
const SECRET_KEY = 'your-secret-key';

// REGISTER ROUTE
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!validator.isEmail(email)) {
    logger.warn(`Invalid email format attempted: ${email}`);
    return res.status(400).send('Invalid email format');
  }

  if (validator.isEmpty(password) || password.length < 6) {
    logger.warn(`Weak password attempt for: ${email}`);
    return res.status(400).send('Password must be at least 6 characters');
  }

  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    logger.warn(`Duplicate registration attempt: ${email}`);
    return res.status(400).send('User already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ email, password: hashedPassword });
  logger.info(`New user registered: ${email}`);
  res.status(201).send('User registered successfully');
});

// LOGIN ROUTE
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!validator.isEmail(email)) {
    logger.warn(`Invalid email format on login: ${email}`);
    return res.status(400).send('Invalid email format');
  }

  const user = users.find(u => u.email === email);
  if (!user) {
    logger.warn(`Failed login - user not found: ${email}`);
    return res.status(400).send('User not found');
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    logger.warn(`Failed login - wrong password for: ${email}`);
    return res.status(400).send('Invalid password');
  }

  const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
  logger.info(`Successful login: ${email}`);
  res.send({ message: 'Login successful', token });
});

// PROTECTED PROFILE ROUTE
app.get('/profile', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logger.warn('Unauthorized profile access attempt - no token');
    return res.status(401).send('Access denied. No token provided.');
  }

  try {
    const verified = jwt.verify(token, SECRET_KEY);
    logger.info(`Profile accessed by: ${verified.email}`);
    res.send({ message: 'Welcome to your profile!', user: verified.email });
  } catch (err) {
    logger.warn('Invalid token used');
    res.status(400).send('Invalid token');
  }
});

app.listen(3000, () => {
  logger.info('Server started on port 3000');
  console.log('Secure app running on http://localhost:3000');
});
