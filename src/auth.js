const jwt = require('jsonwebtoken');

const authenticateUser = (username, password) => { // Consulta de usuarios registrados 
  return users.find(user => user.username === username && user.password === password);
};

const generateToken = (username) => { // Generación de TOKEN para usuarios JWT
    console.log("JWT_SECRET cargado:", process.env.JWT_SECRET); // Respuesta en la terminal cuando cargue un usuario (TOKEN)
    return jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1m' }); // Duración del TOKEN (1 Minuto)
};

module.exports = { authenticateUser, generateToken };