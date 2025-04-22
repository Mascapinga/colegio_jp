const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');

const app = express();
const port = process.env.PORT || 5000;
// SEGURIDAD: Usar variables de entorno para secretos
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === 'production' ? null : '88Zg_7KjXWhWb_!M');

if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  console.error('JWT_SECRET no está definido en el entorno de producción');
  process.exit(1);
}

// Configuración de middlewares
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Configuración de almacenamiento
const uploadPath = path.join(__dirname, '../colegio_jjp/uploads');
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Sanitizar nombre de archivo
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(sanitizedName));
  },
});

// Configuración de multer con validación de archivos
const fileFilter = (req, file, cb) => {
  // Solo permitir imágenes
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Solo se permiten archivos de imagen'), false);
  }
};

const upload = multer({ 
  storage, 
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // Limitar a 5MB
});

// Servir archivos estáticos
app.use('/uploads', express.static(path.join(__dirname, '../colegio_jjp/uploads')));

// Conexión a la base de datos
const dbPath = path.join(__dirname, '../colegio_jjp/colegio.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error connecting to SQLite database:', err);
    process.exit(1);
  }
});

// Función promisificada para DB para evitar callbacks anidados
const runQuery = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(query, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};

const getOne = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

const getAll = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

// Inicialización de la base de datos
const initDb = async () => {
  try {
    await runQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
      )
    `);

    await runQuery(`
      CREATE TABLE IF NOT EXISTS teachers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        turno TEXT NOT NULL,
        nivel TEXT NOT NULL,
        grado TEXT,
        seccion TEXT,
        area TEXT,
        image TEXT
      )
    `);

    await runQuery(`
      CREATE TABLE IF NOT EXISTS administratives (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        cargo TEXT NOT NULL,
        image TEXT
      )
    `);

    await runQuery(`
      CREATE TABLE IF NOT EXISTS directives (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        position TEXT NOT NULL,
        description TEXT NOT NULL,
        level TEXT NOT NULL,
        image TEXT
      )
    `);

    await runQuery(`
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        date TEXT NOT NULL,
        images TEXT
      )
    `);
    
    await runQuery(`
      CREATE TABLE IF NOT EXISTS consultations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        topic TEXT NOT NULL,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `);

    await runQuery(`
      CREATE TABLE IF NOT EXISTS memories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        date TEXT NOT NULL,
        images TEXT
      )
    `);
    
    // Crear índices para mejorar rendimiento
    await runQuery('CREATE INDEX IF NOT EXISTS idx_events_date ON events(date)');
    await runQuery('CREATE INDEX IF NOT EXISTS idx_consultations_created_at ON consultations(created_at)');
    await runQuery('CREATE INDEX IF NOT EXISTS idx_memories_date ON memories(date)');
  } catch (error) {
    console.error('Error initializing database:', error);
    process.exit(1);
  }
};

initDb();

// Middleware de verificación de token
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.status(401).json({ message: 'No autorizado: Token no proporcionado' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Error al verificar token:', error);
    return res.status(401).json({ message: 'No autorizado: Token inválido' });
  }
};

// Middleware de manejo de errores
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Error interno del servidor', error: process.env.NODE_ENV === 'production' ? 'Algo salió mal' : err.message });
};

// Helper para validación
const validate = validations => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    next();
  };
};

// Rutas de autenticación
app.post('/api/auth/login', 
  validate([
    body('email').isEmail().withMessage('Email inválido'),
    body('password').notEmpty().withMessage('Contraseña requerida')
  ]),
  async (req, res) => {
    const { email, password } = req.body;
    
    try {
      const user = await getOne('SELECT * FROM users WHERE email = ?', [email]);
      
      if (!user) {
        return res.status(401).json({ message: 'Email o contraseña incorrectos' });
      }
      
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ message: 'Email o contraseña incorrectos' });
      }
      
      const token = jwt.sign(
        { id: user.id, email: user.email }, 
        JWT_SECRET, 
        { expiresIn: '24h' }
      );
      
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
      });
      
      res.json({ user: { id: user.id, email: user.email } });
    } catch (error) {
      console.error('Error during login:', error);
      res.status(500).json({ message: 'Error al iniciar sesión' });
    }
  }
);

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout exitoso' });
});

app.get('/api/auth/verify', verifyToken, async (req, res) => {
  try {
    const user = await getOne('SELECT id, email FROM users WHERE id = ?', [req.user.id]);
    
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    res.json({ user: { id: user.id, email: user.email } });
  } catch (error) {
    console.error('Error verifying user:', error);
    res.status(500).json({ message: 'Error al verificar usuario' });
  }
});

// API para profesores
app.get('/api/teachers', async (req, res) => {
  try {
    const nivel = req.query.nivel;
    let query = 'SELECT id, name, turno, nivel, grado, seccion, image, area FROM teachers';
    let params = [];
    
    if (nivel) {
      query += ' WHERE nivel = ?';
      params.push(nivel);
    }
    
    const teachers = await getAll(query, params);
    res.json({ data: teachers });
  } catch (error) {
    console.error('Error fetching teachers:', error);
    res.status(500).json({ message: 'Error al obtener docentes' });
  }
});

app.post('/api/teachers', 
  verifyToken, 
  upload.single('image'),
  validate([
    body('name').notEmpty().withMessage('Nombre es requerido'),
    body('turno').notEmpty().withMessage('Turno es requerido'),
    body('nivel').notEmpty().withMessage('Nivel es requerido')
  ]),
  async (req, res) => {
    try {
      const { name, turno, nivel, grado, seccion, area } = req.body;
      const image = req.file ? `/uploads/${req.file.filename}` : null;
      const areaValue = area && area.trim() !== '' ? area : null;
      
      const result = await runQuery(
        'INSERT INTO teachers (name, turno, nivel, grado, seccion, area, image) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [name, turno, nivel, grado || null, seccion || null, areaValue, image]
      );
      
      res.json({ 
        data: { 
          id: result.lastID, 
          name, 
          turno, 
          nivel, 
          grado, 
          seccion, 
          area: areaValue, 
          image 
        } 
      });
    } catch (error) {
      console.error('Error adding teacher:', error);
      res.status(500).json({ message: 'Error al agregar docente' });
    }
  }
);

app.put('/api/teachers/:id', 
  verifyToken, 
  upload.single('image'),
  validate([
    body('name').notEmpty().withMessage('Nombre es requerido'),
    body('turno').notEmpty().withMessage('Turno es requerido'),
    body('nivel').notEmpty().withMessage('Nivel es requerido')
  ]),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, turno, nivel, grado, seccion, area } = req.body;
      const image = req.file ? `/uploads/${req.file.filename}` : req.body.image;
      const areaValue = area !== undefined ? area : null;
      
      const result = await runQuery(
        'UPDATE teachers SET name = ?, turno = ?, nivel = ?, grado = ?, seccion = ?, area = ?, image = ? WHERE id = ?',
        [name, turno, nivel, grado || null, seccion || null, areaValue, image, id]
      );
      
      if (result.changes === 0) {
        return res.status(404).json({ message: 'Docente no encontrado' });
      }
      
      res.json({ 
        data: { 
          id, 
          name, 
          turno, 
          nivel, 
          grado, 
          seccion, 
          area: areaValue, 
          image 
        } 
      });
    } catch (error) {
      console.error('Error updating teacher:', error);
      res.status(500).json({ message: 'Error al actualizar docente' });
    }
  }
);

app.delete('/api/teachers/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Primero verificar si existe la imagen para eliminarla
    const teacher = await getOne('SELECT image FROM teachers WHERE id = ?', [id]);
    
    if (teacher && teacher.image && teacher.image.startsWith('/uploads/')) {
      const imagePath = path.join(__dirname, '../colegio_jjp', teacher.image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }
    
    const result = await runQuery('DELETE FROM teachers WHERE id = ?', [id]);
    
    if (result.changes === 0) {
      return res.status(404).json({ message: 'Docente no encontrado' });
    }
    
    res.json({ message: 'Docente eliminado' });
  } catch (error) {
    console.error('Error deleting teacher:', error);
    res.status(500).json({ message: 'Error al eliminar docente' });
  }
});

// API para administrativos
app.get('/api/administratives', async (req, res) => {
  try {
    const administratives = await getAll('SELECT * FROM administratives');
    res.json({ data: administratives });
  } catch (error) {
    console.error('Error fetching administratives:', error);
    res.status(500).json({ message: 'Error al obtener administrativos' });
  }
});

app.post('/api/administratives', 
  verifyToken, 
  upload.single('image'),
  validate([
    body('name').notEmpty().withMessage('Nombre es requerido'),
    body('cargo').notEmpty().withMessage('Cargo es requerido')
  ]),
  async (req, res) => {
    try {
      const { name, cargo } = req.body;
      const image = req.file ? `/uploads/${req.file.filename}` : null;
      
      const result = await runQuery(
        'INSERT INTO administratives (name, cargo, image) VALUES (?, ?, ?)',
        [name, cargo, image]
      );
      
      res.json({ data: { id: result.lastID, name, cargo, image } });
    } catch (error) {
      console.error('Error adding administrative:', error);
      res.status(500).json({ message: 'Error al agregar administrativo' });
    }
  }
);

app.put('/api/administratives/:id', 
  verifyToken, 
  upload.single('image'),
  validate([
    body('name').notEmpty().withMessage('Nombre es requerido'),
    body('cargo').notEmpty().withMessage('Cargo es requerido')
  ]),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, cargo } = req.body;
      const image = req.file ? `/uploads/${req.file.filename}` : req.body.image;
      
      const result = await runQuery(
        'UPDATE administratives SET name = ?, cargo = ?, image = ? WHERE id = ?',
        [name, cargo, image, id]
      );
      
      if (result.changes === 0) {
        return res.status(404).json({ message: 'Administrativo no encontrado' });
      }
      
      res.json({ data: { id, name, cargo, image } });
    } catch (error) {
      console.error('Error updating administrative:', error);
      res.status(500).json({ message: 'Error al actualizar administrativo' });
    }
  }
);

app.delete('/api/administratives/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Similar a teachers, eliminar la imagen si existe
    const administrative = await getOne('SELECT image FROM administratives WHERE id = ?', [id]);
    
    if (administrative && administrative.image && administrative.image.startsWith('/uploads/')) {
      const imagePath = path.join(__dirname, '../colegio_jjp', administrative.image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }
    
    const result = await runQuery('DELETE FROM administratives WHERE id = ?', [id]);
    
    if (result.changes === 0) {
      return res.status(404).json({ message: 'Administrativo no encontrado' });
    }
    
    res.json({ message: 'Administrativo eliminado' });
  } catch (error) {
    console.error('Error deleting administrative:', error);
    res.status(500).json({ message: 'Error al eliminar administrativo' });
  }
});

// API para directivos
app.get('/api/directives', async (req, res) => {
  try {
    const directives = await getAll('SELECT * FROM directives');
    res.json({ data: directives });
  } catch (error) {
    console.error('Error fetching directives:', error);
    res.status(500).json({ message: 'Error al obtener directivos' });
  }
});

app.post('/api/directives', 
  verifyToken, 
  upload.single('image'),
  validate([
    body('name').notEmpty().withMessage('Nombre es requerido'),
    body('position').notEmpty().withMessage('Posición es requerida'),
    body('description').notEmpty().withMessage('Descripción es requerida'),
    body('level').notEmpty().withMessage('Nivel es requerido')
  ]),
  async (req, res) => {
    try {
      const { name, position, description, level } = req.body;
      const image = req.file ? `/uploads/${req.file.filename}` : null;
      
      const result = await runQuery(
        'INSERT INTO directives (name, position, description, level, image) VALUES (?, ?, ?, ?, ?)',
        [name, position, description, level, image]
      );
      
      res.json({ 
        data: { 
          id: result.lastID, 
          name, 
          position, 
          description, 
          level, 
          image 
        } 
      });
    } catch (error) {
      console.error('Error adding directive:', error);
      res.status(500).json({ message: 'Error al agregar directivo' });
    }
  }
);

app.put('/api/directives/:id', 
  verifyToken, 
  upload.single('image'),
  validate([
    body('name').notEmpty().withMessage('Nombre es requerido'),
    body('position').notEmpty().withMessage('Posición es requerida'),
    body('description').notEmpty().withMessage('Descripción es requerida'),
    body('level').notEmpty().withMessage('Nivel es requerido')
  ]),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, position, description, level } = req.body;
      const image = req.file ? `/uploads/${req.file.filename}` : req.body.image;
      
      const result = await runQuery(
        'UPDATE directives SET name = ?, position = ?, description = ?, level = ?, image = ? WHERE id = ?',
        [name, position, description, level, image, id]
      );
      
      if (result.changes === 0) {
        return res.status(404).json({ message: 'Directivo no encontrado' });
      }
      
      res.json({ 
        data: { 
          id, 
          name, 
          position, 
          description, 
          level, 
          image 
        } 
      });
    } catch (error) {
      console.error('Error updating directive:', error);
      res.status(500).json({ message: 'Error al actualizar directivo' });
    }
  }
);

app.delete('/api/directives/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Similar a los anteriores, eliminar la imagen si existe
    const directive = await getOne('SELECT image FROM directives WHERE id = ?', [id]);
    
    if (directive && directive.image && directive.image.startsWith('/uploads/')) {
      const imagePath = path.join(__dirname, '../colegio_jjp', directive.image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }
    
    const result = await runQuery('DELETE FROM directives WHERE id = ?', [id]);
    
    if (result.changes === 0) {
      return res.status(404).json({ message: 'Directivo no encontrado' });
    }
    
    res.json({ message: 'Directivo eliminado' });
  } catch (error) {
    console.error('Error deleting directive:', error);
    res.status(500).json({ message: 'Error al eliminar directivo' });
  }
});

// API para eventos
app.get('/api/events', async (req, res) => {
  try {
    const rows = await getAll('SELECT * FROM events ORDER BY date DESC');
    
    const events = rows.map(row => ({
      ...row,
      images: row.images ? JSON.parse(row.images) : [],
    }));
    
    res.json({ data: events });
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ message: 'Error al obtener eventos' });
  }
});

app.post('/api/events', 
  verifyToken, 
  upload.array('images', 10),
  validate([
    body('title').notEmpty().withMessage('Título es requerido'),
    body('date').notEmpty().isISO8601().withMessage('Fecha inválida')
  ]),
  async (req, res) => {
    try {
      const { title, date } = req.body;
      const images = req.files.map(file => `/uploads/${file.filename}`);
      const imagesJson = JSON.stringify(images);
      
      const result = await runQuery(
        'INSERT INTO events (title, date, images) VALUES (?, ?, ?)',
        [title, date, imagesJson]
      );
      
      res.json({ data: { id: result.lastID, title, date, images } });
    } catch (error) {
      console.error('Error adding event:', error);
      res.status(500).json({ message: 'Error al agregar evento' });
    }
  }
);

app.put('/api/events/:id', 
  verifyToken, 
  upload.array('images', 10),
  validate([
    body('title').notEmpty().withMessage('Título es requerido'),
    body('date').notEmpty().isISO8601().withMessage('Fecha inválida')
  ]),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { title, date } = req.body;
      
      let images;
      if (req.files.length > 0) {
        images = req.files.map(file => `/uploads/${file.filename}`);
      } else {
        try {
          images = JSON.parse(req.body.images || '[]');
        } catch (e) {
          images = [];
        }
      }
      
      const imagesJson = JSON.stringify(images);
      
      const result = await runQuery(
        'UPDATE events SET title = ?, date = ?, images = ? WHERE id = ?',
        [title, date, imagesJson, id]
      );
      
      if (result.changes === 0) {
        return res.status(404).json({ message: 'Evento no encontrado' });
      }
      
      res.json({ data: { id, title, date, images } });
    } catch (error) {
      console.error('Error updating event:', error);
      res.status(500).json({ message: 'Error al actualizar evento' });
    }
  }
);

app.delete('/api/events/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Obtener las imágenes del evento para eliminarlas
    const event = await getOne('SELECT images FROM events WHERE id = ?', [id]);
    
    if (event && event.images) {
      try {
        const images = JSON.parse(event.images);
        for (const imagePath of images) {
          if (imagePath.startsWith('/uploads/')) {
            const fullPath = path.join(__dirname, '../colegio_jjp', imagePath);
            if (fs.existsSync(fullPath)) {
              fs.unlinkSync(fullPath);
            }
          }
        }
      } catch (e) {
        console.error('Error parsing images JSON:', e);
      }
    }
    
    const result = await runQuery('DELETE FROM events WHERE id = ?', [id]);
    
    if (result.changes === 0) {
      return res.status(404).json({ message: 'Evento no encontrado' });
    }
    
    res.json({ message: 'Evento eliminado' });
  } catch (error) {
    console.error('Error deleting event:', error);
    res.status(500).json({ message: 'Error al eliminar evento' });
  }
});

// API para memorias
app.get('/api/memories', async (req, res) => {
  try {
    const rows = await getAll('SELECT * FROM memories ORDER BY date DESC');
    
    const memories = rows.map(row => ({
      ...row,
      images: row.images ? JSON.parse(row.images) : [],
    }));
    
    res.json({ data: memories });
  } catch (error) {
    console.error('Error fetching memories:', error);
    res.status(500).json({ message: 'Error al obtener memorias' });
  }
});

app.post('/api/memories', 
  verifyToken, 
  upload.array('images', 10),
  validate([
    body('title').notEmpty().withMessage('Título es requerido'),
    body('date').notEmpty().isISO8601().withMessage('Fecha inválida')
  ]),
  async (req, res) => {
    try {
      const { title, date } = req.body;
      const images = req.files.map(file => `/uploads/${file.filename}`);
      const imagesJson = JSON.stringify(images);
      
      const result = await runQuery(
        'INSERT INTO memories (title, date, images) VALUES (?, ?, ?)',
        [title, date, imagesJson]
      );
      
      res.json({ data: { id: result.lastID, title, date, images } });
    } catch (error) {
      console.error('Error adding memory:', error);
      res.status(500).json({ message: 'Error al agregar memoria' });
    }
  }
);

app.put('/api/memories/:id', 
  verifyToken, 
  upload.array('images', 10),
  validate([
    body('title').notEmpty().withMessage('Título es requerido'),
    body('date').notEmpty().isISO8601().withMessage('Fecha inválida')
  ]),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { title, date } = req.body;
      
      let images;
      if (req.files.length > 0) {
        images = req.files.map(file => `/uploads/${file.filename}`);
      } else {
        try {
          images = JSON.parse(req.body.images || '[]');
        } catch (e) {
          images = [];
        }
      }
      
      const imagesJson = JSON.stringify(images);
      
      const result = await runQuery(
        'UPDATE memories SET title = ?, date = ?, images = ? WHERE id = ?',
        [title, date, imagesJson, id]
      );
      
      if (result.changes === 0) {
        return res.status(404).json({ message: 'Memoria no encontrada' });
      }
      
      res.json({ data: { id, title, date, images } });
    } catch (error) {
      console.error('Error updating memory:', error);
      res.status(500).json({ message: 'Error al actualizar memoria' });
    }
  }
);

app.delete('/api/memories/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Obtener las imágenes de la memoria para eliminarlas
    const memory = await getOne('SELECT images FROM memories WHERE id = ?', [id]);
    
    if (memory && memory.images) {
      try {
        const images = JSON.parse(memory.images);
        for (const imagePath of images) {
          if (imagePath.startsWith('/uploads/')) {
            const fullPath = path.join(__dirname, '../colegio_jjp', imagePath);
            if (fs.existsSync(fullPath)) {
              fs.unlinkSync(fullPath);
            }
          }
        }
      } catch (e) {
        console.error('Error parsing images JSON:', e);
      }
    }
    
    const result = await runQuery('DELETE FROM memories WHERE id = ?', [id]);
    
    if (result.changes === 0) {
      return res.status(404).json({ message: 'Memoria no encontrada' });
    }
    
    res.json({ message: 'Memoria eliminada' });
  } catch (error) {
    console.error('Error deleting memory:', error);
    res.status(500).json({ message: 'Error al eliminar memoria' });
  }
});

// API para consultas
app.post('/api/consultations', 
  validate([
    body('topic').notEmpty().withMessage('Tema es requerido'),
    body('name').notEmpty().withMessage('Nombre es requerido'),
    body('email').isEmail().withMessage('Email inválido'),
    body('message').notEmpty().withMessage('Mensaje es requerido')
  ]),
  async (req, res) => {
    try {
      const { topic, name, email, message } = req.body;
      const createdAt = new Date().toISOString();
      
      const result = await runQuery(
        'INSERT INTO consultations (topic, name, email, message, created_at) VALUES (?, ?, ?, ?, ?)',
        [topic, name, email, message, createdAt]
      );
      
      res.json({ 
        message: 'Consulta enviada con éxito', 
        data: { 
          id: result.lastID, 
          topic, 
          name, 
          email, 
          message, 
          created_at: createdAt 
        } 
      });
    } catch (error) {
      console.error('Error adding consultation:', error);
      res.status(500).json({ message: 'Error al guardar la consulta' });
    }
  }
);

app.get('/api/consultations', verifyToken, async (req, res) => {
  try {
    const consultations = await getAll('SELECT * FROM consultations ORDER BY created_at DESC');
    res.json({ data: consultations });
  } catch (error) {
    console.error('Error fetching consultations:', error);
    res.status(500).json({ message: 'Error al obtener las consultas' });
  }
});

// Middleware de manejo de errores (debe estar al final)
app.use(errorHandler);

// Manejador de cierre limpio
process.on('SIGINT', () => {
  db.close(() => {
    console.log('Conexión a la base de datos cerrada');
    process.exit(0);
  });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});