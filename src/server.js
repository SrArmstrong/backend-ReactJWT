require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');
const { generateToken } = require('./auth');
const jwt = require('jsonwebtoken');
const serviceAccount = require('./config/firebase-key.json');

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

    return {
        username: userData.username,
        email: userData.email,
        role: userData.role,
        created_at: userData.created_at,
        last_login: userData.last_login
    };
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // El token se envía en el header "Authorization: Bearer TOKEN"

    if (!token) {
        return res.status(401).json({ statusCode: 401, message: 'Acceso denegado. Token no proporcionado' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ statusCode: 403, message: 'Token inválido o expirado' });
        }

        req.user = decoded;
        next();
    });
};

const authorizePermission = (requiredPermission) => {
    return async (req, res, next) => {
        try {
            // Obtener el rol del usuario desde la solicitud
            const userRole = req.user.role;

            // Buscar los permisos en la colección ROLES donde el nombre del documento sea el mismo que el rol
            const roleDoc = await db.collection('ROLES').doc(userRole).get();

            if (!roleDoc.exists) {
                return res.status(403).json({ statusCode: 403, message: 'Acceso denegado. El rol no tiene permisos asignados' });
            }

            const roleData = roleDoc.data();

            // Verificar si el usuario tiene el permiso requerido
            if (!roleData.permissions || !roleData.permissions.includes(requiredPermission)) {
                return res.status(403).json({ statusCode: 403, message: 'Acceso denegado. No tienes el permiso necesario' });
            }

            next();
        } catch (error) {
            return res.status(500).json({ message: 'Error al verificar permisos', error: error.message });
        }
    };
};


// Verificar si el usuario es admin
const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ statusCode: 403, message: 'Acceso denegado. Se requieren privilegios de administrador' });
    }
    next();
};

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

      // Desencriptación de TOKEN
      const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

      return res.status(200).json({
        statusCode: 200,
        intDataMessage: [{ token: token }],
        userInfo: {
            username: user.username,
            email: user.email,
            role: user.role,
            created_at: user.created_at,
            last_login: lastLoginTime.seconds}
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
  
        // Definir los permisos según el rol
        let permissions = [];
        if (role === 'admin') {
            permissions = ["getUsers", "getRoles", "deleteUsers", "updateUsers", "updateRol", "addRol", "deleteRol", "addPermission", "deletePermissions"];
        } else if (role === 'user') {
            permissions = ['updateUsers'];
        }
  
        //const roleRef = db.collection('ROLES').doc(`${username}_${email}`);
        const roleRef = db.collection('ROLES').doc(username);
        await roleRef.set({
            role,
            permissions
        });        
  
        return res.status(201).json({ statusCode: 201, message: 'Usuario registrado exitosamente' });
    } catch (error) {
        return res.status(500).json({ statusCode: 500, message: 'Error en el servidor', error: error.message });
    }
  });


// Obtener todos los usuarios
app.get('/getUsers', authenticateToken, authorizePermission('getUsers'), async (req, res) => {
    try {
        const snapshot = await db.collection('USERS').get();
        const users = snapshot.docs.map(doc => doc.data());
        return res.status(200).json(users);
    } catch (error) {
        return res.status(500).json({ message: 'Error al obtener usuarios', error: error.message });
    }
});

// Obtener todos los usuarios
app.get('/getRoles', authenticateToken, authorizePermission('getRoles'), async (req, res) => {
    try {
        const snapshot = await db.collection('ROLES').get();
        const users = snapshot.docs.map(doc => doc.data());
        return res.status(200).json(users);
    } catch (error) {
        return res.status(500).json({ message: 'Error al obtener los roles', error: error.message });
    }
});

// Eliminar un usuario por username
app.delete('/deleteUsers/:username', authenticateToken, authorizePermission('deleteUsers'), async (req, res) => {
    const { username } = req.params;

    try {
        await db.collection('USERS').doc(username).delete();
        return res.status(200).json({ message: 'Usuario eliminado exitosamente' });
    } catch (error) {
        return res.status(500).json({ message: 'Error al eliminar usuario', error: error.message });
    }
});

// Actualizar información de un usuario
app.put('/updateUsers/:username', authenticateToken, authorizePermission('updateUsers'), async (req, res) => {
    const { username } = req.params;
    const updateData = req.body;
    try {
        await db.collection('USERS').doc(username).update(updateData);
        return res.status(200).json({ message: 'Usuario actualizado exitosamente' });
    } catch (error) {
        return res.status(500).json({ message: 'Error al actualizar usuario', error: error.message });
    }
});

// Actualizar rol de un usuario
app.put('/updateRol/:username',authenticateToken, authorizePermission('updateRol'), async (req, res) => {
    const { username } = req.params;
    const { role } = req.body;
    try {
        await db.collection('USERS').doc(username).update({ role });
        return res.status(200).json({ message: 'Rol actualizado exitosamente' });
    } catch (error) {
        return res.status(500).json({ message: 'Error al actualizar rol', error: error.message });
    }
});

// Agregar un nuevo rol
app.post('/addRol',authenticateToken, authorizePermission('addRol'), async (req, res) => {
    const { role, permissions } = req.body;
    try {
        await db.collection('ROLES').doc(role).set({ permissions });
        return res.status(201).json({ message: 'Rol agregado exitosamente' });
    } catch (error) {
        return res.status(500).json({ message: 'Error al agregar rol', error: error.message });
    }
});

// Eliminar un rol
app.delete('/deleteRol/:role',authenticateToken, authorizePermission('deleteRol'), async (req, res) => {
    const { role } = req.params;
    try {
        await db.collection('ROLES').doc(role).delete();
        return res.status(200).json({ message: 'Rol eliminado exitosamente' });
    } catch (error) {
        return res.status(500).json({ message: 'Error al eliminar rol', error: error.message });
    }
});

// Agregar un permiso a un rol
app.post('/addPermissions:/role',authenticateToken, authorizePermission('addPermissions'), async (req, res) => {
    const { role, permission } = req.body;
    try {
        const roleRef = db.collection('ROLES').doc(role);
        const roleDoc = await roleRef.get();
        if (!roleDoc.exists) {
            return res.status(404).json({ message: 'Rol no encontrado' });
        }
        const permissions = roleDoc.data().permissions || [];
        permissions.push(permission);
        await roleRef.update({ permissions });
        return res.status(200).json({ message: 'Permiso agregado exitosamente' });
    } catch (error) {
        return res.status(500).json({ message: 'Error al agregar permiso', error: error.message });
    }
});

// Eliminar un permiso de un rol
app.delete('/deletePermissions/:role/:permission',authenticateToken, authorizePermission('deletePermissions'), async (req, res) => {
    const { role, permission } = req.params;
    try {
        const roleRef = db.collection('ROLES').doc(role);
        const roleDoc = await roleRef.get();
        if (!roleDoc.exists) {
            return res.status(404).json({ message: 'Rol no encontrado' });
        }
        let permissions = roleDoc.data().permissions || [];
        permissions = permissions.filter(p => p !== permission);
        await roleRef.update({ permissions });
        return res.status(200).json({ message: 'Permiso eliminado exitosamente' });
    } catch (error) {
        return res.status(500).json({ message: 'Error al eliminar permiso', error: error.message });
    }
});

// Puerto predefinido
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});