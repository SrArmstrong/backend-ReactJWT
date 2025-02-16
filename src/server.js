require('dotenv').config(); // Load environment variables
const express = require('express');
const cors = require('cors');
const { authenticateUser, generateToken } = require('./auth');

const app = express();
app.use(cors());
app.use(express.json());

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ statusCode: 400, message: 'Username y password son requeridos' });
  }

  const user = authenticateUser(username, password);
  if (!user) {
    return res.status(401).json({ statusCode: 401, message: 'Credenciales inválidas' });
  }

  const token = generateToken(username);
  return res.status(200).json({
    statusCode: 200,
    intDataMessage: [{ token: token }]
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});