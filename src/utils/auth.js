const jwt = require('jsonwebtoken');
const db = require('../config/database');
const { logToDB } = require('./logger');

// Vérification du token JWT
const authenticate = (req, res, next) => {
  // Récupérer le token depuis les cookies
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).redirect('/login');
  }

  try {
    // Vérifier le token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // Vérifier si le token existe dans la base de données
    const query = `SELECT * FROM sessions WHERE token = ? AND expires_at > datetime('now')`;
    
    db.get(query, [token], (err, session) => {
      if (err || !session) {
        return res.status(401).redirect('/login');
      }
      
      // Logger l'activité
      logToDB(
        decoded.id, 
        'AUTH_SUCCESS', 
        req.ip, 
        req.headers['user-agent']
      );
      
      next();
    });
  } catch (error) {
    // Logger la tentative échouée
    logToDB(
      null, 
      'AUTH_FAILURE', 
      req.ip, 
      req.headers['user-agent'], 
      { error: error.message }
    );
    
    res.status(401).redirect('/login');
  }
};

// Middleware pour vérifier le code A2F
const A2F = (req, res, next) => {
  const { userId, twoFactorVerified } = req.session;
  
  if (!userId || !twoFactorVerified) {
    return res.redirect('/verify-code');
  }
  
  next();
};

module.exports = {
  authenticate,
  A2F
};