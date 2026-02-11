const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configuración de PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Crear tabla de usuarios
(async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        nivel VARCHAR(20) DEFAULT 'usuario'
      );
    `);
    console.log('Tabla usuarios lista');
  } finally {
    client.release();
  }
})();

// Ruta de registro
app.post('/register', async (req, res) => {
  const { nombre, email, password, nivel = 'usuario' } = req.body;

  if (!nombre || !email || !password) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nombre, email, password, nivel) VALUES ($1, $2, $3, $4) RETURNING id, nombre, email, nivel',
      [nombre, email, hashedPassword, nivel]
    );
    res.status(201).json({ mensaje: 'Usuario registrado', usuario: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Ruta de login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña requeridos' });
  }

  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    const usuario = result.rows[0];

    if (!usuario || !(await bcrypt.compare(password, usuario.password))) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }
  
// Middleware para verificar token JWT
const verificarToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(403).json({ error: 'Token requerido' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secreto');
    req.usuario = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
};

// Middleware para verificar si es admin
const verificarAdmin = (req, res, next) => {
  if (req.usuario.nivel !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado. Se requiere rol de administrador' });
  }
  next();
};

// Crear tabla de productos
(async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS productos (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(200) NOT NULL,
        codigo VARCHAR(50) UNIQUE NOT NULL,
        precio DECIMAL(10,2) NOT NULL CHECK (precio > 0),
        descripcion TEXT,
        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        creado_por INTEGER REFERENCES usuarios(id)
      );
    `);
    console.log('Tabla productos lista');
  } finally {
    client.release();
  }
})();

// RUTAS DE PRODUCTOS

// 1. Crear producto (solo admin)
app.post('/productos', verificarToken, verificarAdmin, async (req, res) => {
  const { nombre, codigo, precio, descripcion } = req.body;
  const creado_por = req.usuario.id;

  if (!nombre || !codigo || !precio) {
    return res.status(400).json({ error: 'Nombre, código y precio son obligatorios' });
  }

  if (precio <= 0) {
    return res.status(400).json({ error: 'El precio debe ser mayor a 0' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO productos (nombre, codigo, precio, descripcion, creado_por) 
      VALUES ($1, $2, $3, $4, $5) 
      RETURNING id, nombre, codigo, precio, descripcion, fecha_creacion`,
      [nombre, codigo, precio, descripcion || '', creado_por]
    );
    res.status(201).json({ mensaje: 'Producto creado', producto: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') { // Violación de unique constraint
      return res.status(400).json({ error: 'El código del producto ya existe' });
    }
    console.error(error);
    res.status(500).json({ error: 'Error al crear producto' });
  }
});

// 2. Ver todos los productos (público o con token)
app.get('/productos', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.nombre as creador 
      FROM productos p 
      LEFT JOIN usuarios u ON p.creado_por = u.id 
      ORDER BY p.fecha_creacion DESC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener productos' });
  }
});

// 3. Ver producto por código (público o con token)
app.get('/productos/:codigo', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.nombre as creador 
      FROM productos p 
      LEFT JOIN usuarios u ON p.creado_por = u.id 
      WHERE p.codigo = $1`,
      [req.params.codigo]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener producto' });
  }
});

// 4. Actualizar producto (solo admin)
app.put('/productos/:id', verificarToken, verificarAdmin, async (req, res) => {
  const { id } = req.params;
  const { nombre, precio, descripcion } = req.body;

  if (precio && precio <= 0) {
    return res.status(400).json({ error: 'El precio debe ser mayor a 0' });
  }

  try {
    const result = await pool.query(
      `UPDATE productos 
      SET nombre = COALESCE($1, nombre), 
      precio = COALESCE($2, precio), 
      descripcion = COALESCE($3, descripcion) 
      WHERE id = $4 
      RETURNING *`,
      [nombre, precio, descripcion, id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    
    res.json({ mensaje: 'Producto actualizado', producto: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar producto' });
  }
});

// 5. Eliminar producto (solo admin)
app.delete('/productos/:id', verificarToken, verificarAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM productos WHERE id = $1 RETURNING *', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    
    res.json({ mensaje: 'Producto eliminado', producto: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al eliminar producto' });
  }
});

// ========== CARRITO DE COMPRAS ==========

// Crear tabla de carritos
(async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS carritos (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
        producto_id INTEGER REFERENCES productos(id) ON DELETE CASCADE,
        cantidad INTEGER NOT NULL DEFAULT 1 CHECK (cantidad > 0),
        fecha_agregado TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(usuario_id, producto_id) -- Evita duplicados
      );
    `);
    console.log('Tabla carritos lista');
  } finally {
    client.release();
  }
})();

// 1. Agregar producto al carrito
app.post('/carrito', verificarToken, async (req, res) => {
  const { producto_id, cantidad = 1 } = req.body;
  const usuario_id = req.usuario.id;

  if (!producto_id) {
    return res.status(400).json({ error: 'producto_id es requerido' });
  }

  if (cantidad <= 0) {
    return res.status(400).json({ error: 'La cantidad debe ser mayor a 0' });
  }

  try {
    // Verificar que el producto existe
    const productoCheck = await pool.query('SELECT id FROM productos WHERE id = $1', [producto_id]);
    if (productoCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    // Usar UPSERT (INSERT o UPDATE si ya existe)
    const result = await pool.query(`
      INSERT INTO carritos (usuario_id, producto_id, cantidad) 
      VALUES ($1, $2, $3)
      ON CONFLICT (usuario_id, producto_id) 
      DO UPDATE SET cantidad = carritos.cantidad + EXCLUDED.cantidad
      RETURNING id, usuario_id, producto_id, cantidad, fecha_agregado
    `, [usuario_id, producto_id, cantidad]);

    res.status(201).json({ 
      mensaje: 'Producto agregado al carrito', 
      item: result.rows[0] 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al agregar al carrito' });
  }
});

// 2. Ver mi carrito con total calculado
app.get('/carrito', verificarToken, async (req, res) => {
  const usuario_id = req.usuario.id;

  try {
    const result = await pool.query(`
      SELECT 
        c.id,
        c.producto_id,
        c.cantidad,
        c.fecha_agregado,
        p.nombre,
        p.codigo,
        p.precio,
        p.descripcion,
        (p.precio * c.cantidad) as subtotal
      FROM carritos c
      JOIN productos p ON c.producto_id = p.id
      WHERE c.usuario_id = $1
      ORDER BY c.fecha_agregado DESC
    `, [usuario_id]);

    // Calcular total general
    const total = result.rows.reduce((sum, item) => sum + parseFloat(item.subtotal), 0);

    res.json({
      items: result.rows,
      total: total.toFixed(2),
      cantidad_items: result.rows.length
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener el carrito' });
  }
});

// 3. Actualizar cantidad en el carrito
app.put('/carrito/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { cantidad } = req.body;
  const usuario_id = req.usuario.id;

  if (!cantidad || cantidad <= 0) {
    return res.status(400).json({ error: 'Cantidad debe ser mayor a 0' });
  }

  try {
    const result = await pool.query(`
      UPDATE carritos 
      SET cantidad = $1 
      WHERE id = $2 AND usuario_id = $3
      RETURNING *
    `, [cantidad, id, usuario_id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Item no encontrado en tu carrito' });
    }

    res.json({ 
      mensaje: 'Cantidad actualizada', 
      item: result.rows[0] 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar el carrito' });
  }
});

// 4. Eliminar item del carrito
app.delete('/carrito/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const usuario_id = req.usuario.id;

  try {
    const result = await pool.query(`
      DELETE FROM carritos 
      WHERE id = $1 AND usuario_id = $2
      RETURNING *
    `, [id, usuario_id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Item no encontrado en tu carrito' });
    }

    res.json({ 
      mensaje: 'Producto eliminado del carrito', 
      item: result.rows[0] 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al eliminar del carrito' });
  }
});

// 5. Vaciar carrito completo
app.delete('/carrito', verificarToken, async (req, res) => {
  const usuario_id = req.usuario.id;

  try {
    const result = await pool.query(`
      DELETE FROM carritos 
      WHERE usuario_id = $1
      RETURNING *
    `, [usuario_id]);

    res.json({ 
      mensaje: 'Carrito vaciado', 
      items_eliminados: result.rows.length 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al vaciar el carrito' });
  }
});

    // Generar token simple
    const token = jwt.sign(
      { id: usuario.id, email: usuario.email, nivel: usuario.nivel },
      process.env.JWT_SECRET || 'secreto',
      { expiresIn: '1h' }
    );

    res.json({ mensaje: 'Login exitoso', token, usuario: { nombre: usuario.nombre, email: usuario.email, nivel: usuario.nivel } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});