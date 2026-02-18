
import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import pg from "pg";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import fs from "fs";

dotenv.config();

const uploadDir = "uploads";

// Crear carpeta si no existe
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueName = Date.now() + "_" + file.originalname;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.get("/", (req, res) => {
  res.redirect("/admin");
});
app.get("/formulario", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "formulario.html"));
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initAdmin() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );
  `);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS documentos (
    id SERIAL PRIMARY KEY,
    alumno_nombre TEXT NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    archivo_nombre TEXT NOT NULL
  );
`);


  const user = process.env.ADMIN_USER;
  const pass = process.env.ADMIN_PASS;

  if (!user || !pass) return;

  const result = await pool.query(
    "SELECT * FROM admins WHERE username=$1",
    [user]
  );

  if (result.rows.length === 0) {
    const hashed = await bcrypt.hash(pass, 10);
    await pool.query(
      "INSERT INTO admins (username, password) VALUES ($1, $2)",
      [user, hashed]
    );
    console.log("Admin creado desde variables de entorno");
  }
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/admin");
  }
  next();
}

app.post("/api/documentos", requireAuth, async (req, res) => {
  try {
    const { alumno_nombre, archivo_nombre } = req.body;

    if (!alumno_nombre || !archivo_nombre) {
      return res.status(400).json({ error: "Faltan datos" });
    }

    const result = await pool.query(
      "INSERT INTO documentos (alumno_nombre, archivo_nombre) VALUES ($1, $2) RETURNING *",
      [alumno_nombre, archivo_nombre]
    );

    res.json(result.rows[0]);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

app.get("/api/documentos", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM documentos ORDER BY fecha_creacion DESC"
    );

    res.json(result.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});



app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "admin.html"));
});

app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM admins WHERE username=$1",
    [username]
  );

  if (result.rows.length === 0) {
    return res.send("Usuario no encontrado");
  }

  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password);

  if (!valid) {
    return res.send("Contraseña incorrecta");
  }

  req.session.user = user.username;
  res.redirect("/dashboard");
});

app.post("/api/upload", requireAuth, upload.single("pdf"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No se subió archivo" });
  }

  res.json({
    message: "Archivo guardado localmente",
    filename: req.file.filename
  });
});

app.use("/uploads", express.static("uploads"));

app.get("/dashboard", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "dashboard.html"));
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/admin");
});

app.listen(PORT, async () => {
  await initAdmin();
  console.log("Servidor corriendo en puerto", PORT);
});
