const winston = require('winston');
const path = require('path');
const fs = require('fs');
const db = require('../config/database');

// Assurer que le dossier de logs existe
const logDir = path.resolve(__dirname, '../../logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// Configuration Winston
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'auth-service' },
  transports: [
    new winston.transports.File({ filename: path.join(logDir, 'error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(logDir, 'combined.log') }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Fonction pour enregistrer les logs dans la base de données
const logToDB = (userId, action, ipAddress, userAgent, details = null) => {
  
  // Préparer les détails au format JSON si c'est un objet
  const detailsStr = details ? (typeof details === 'object' ? JSON.stringify(details) : details) : null;
  
  const query = `INSERT INTO logs (user_id, action, ip_address, user_agent, details) 
                VALUES (?, ?, ?, ?, ?)`;
  
  db.run(query, [userId, action, ipAddress, userAgent, detailsStr], function(err) {
    if (err) {
      logger.error('Erreur lors de l\'enregistrement du log dans la BDD', { error: err.message });
    }
  });
  
  // Logger dans Winston
  logger.info(action, { 
    userId, 
    ipAddress, 
    userAgent, 
    details 
  });
};

// Log de démarrage du serveur
const logServerStart = (port) => {
  const serverStartTime = new Date().toISOString();
  logger.info(`Serveur démarré sur le port ${port} à ${serverStartTime}`);
  
  const query = `INSERT INTO logs (action, details) VALUES (?, ?)`;
  db.run(query, ['SERVER_START', `Port: ${port}, Time: ${serverStartTime}`], function(err) {
    if (err) {
      logger.error('Erreur lors de l\'enregistrement du démarrage serveur', { error: err.message });
    }
  });
};

module.exports = {
  logger,
  logToDB,
  logServerStart
};