require('dotenv').config();
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const { logger, logServerStart } = require('./utils/logger');

const app = express();
const port = process.env.PORT || 3000;

// Protection contre les attaques XSS
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  }
}))

// Configuration CORS
app.use(cors({
  origin: process.env.APP_URL,
  credentials: true
}));

// Configuration du moteur de template
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Middleware pour les données JSON et URL-encoded
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware pour les cookies
app.use(cookieParser());


app.use(session({
  secret: process.env.JWT_SECRET,
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 heures
  }
}));

app.use(express.static(path.join(__dirname, '../public')));

// Routes
app.use('/', require('./routes/index'));
app.use('/auth', require('./routes/auth'));

// Capture des erreurs 404
app.use((req, res, next) => {
  res.status(404).json({ message: "page non trouvée"});
});

app.use((err, req, res, next) => {
    res.status(err.status || 500).json({ message: err.message });
});


// Démarrage du serveur
app.listen(port, () => {
  logServerStart(port);
  console.log(`Serveur démarré sur http://localhost:${port}`);
});

module.exports = app;