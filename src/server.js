require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');
const { generateToken } = require('./auth');
const serviceAccount = require('./firebase-key.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const app = express();
app.use(cors());
app.use(express.json());

async function authenticateUser(username, password) { // Conexión y comparación con la colección USERS
    const usersSnapshot = await db.collection('USERS')
        .where('username', '==', username)
        .get();

    if (usersSnapshot.empty) {
        return null;
    }

    const userData = usersSnapshot.docs[0].data();
    
    // Verificar la contraseña encriptada
    const isMatch = await bcrypt.compare(password, userData.password);
    if (!isMatch) {
        return null;
    }

    return userData;
}

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ statusCode: 400, message: 'Username y password son requeridos' });
    }

    const user = await authenticateUser(username, password);
    if (!user) {
        return res.status(401).json({ statusCode: 401, message: 'Credenciales inválidas' });
    }

    const token = generateToken(username);
    const lastLoginTime = admin.firestore.Timestamp.now();


    try {
      // Actualizar la ultima conección del Usuario
      await db.collection('USERS').doc(username).update({
          last_login: lastLoginTime
      });

      return res.status(200).json({
        statusCode: 200,
        intDataMessage: [{ token: token }],
        last_login: lastLoginTime.seconds
      });

    } catch (error) {
        return res.status(500).json({ statusCode: 500, message: 'Error al actualizar last_login', error: error.message });
    }

});



app.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;

  if (!username || !email || !password || !role) {
      return res.status(400).json({ statusCode: 400, message: 'Todos los campos son requeridos' });
  }

  try {
      const userRef = db.collection('USERS').doc(username);
      const doc = await userRef.get();

      if (doc.exists) {
          return res.status(400).json({ statusCode: 400, message: 'El usuario ya existe' });
      }

      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      await userRef.set({
          username,
          email,
          password: hashedPassword,
          role,
          last_login: null
      });

      return res.status(201).json({ statusCode: 201, message: 'Usuario registrado exitosamente' });
  } catch (error) {
      return res.status(500).json({ statusCode: 500, message: 'Error en el servidor', error: error.message });
  }
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});