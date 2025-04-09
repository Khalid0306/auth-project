const nodemailer = require('nodemailer');
const { logger } = require('./logger');

// Configuration du transporteur d'emails avec gestion améliorée des erreurs
const createTransporter = () => {
  return nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_PORT) || 465,
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    },
    // Paramètres de stabilité de connexion
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,

    tls: {
      rejectUnauthorized: true, // Vérifie le certificat SSL/TLS
      minVersion: 'TLSv1.2' // Utilise TLS 1.2
    },
  });
};

//transporteur avec mécanisme de nouvelle tentative
let transporter = createTransporter();
let retryCount = 0;
const MAX_RETRIES = 3;

// Fonction pour réinitialiser le transporteur
const resetTransporter = () => {
  if (transporter) {
    try {
      transporter.close();
    } catch (error) {
      logger.warn('Erreur lors de la fermeture du transporteur', { error: error.message });
    }
  }
  transporter = createTransporter();
  retryCount = 0;
};

// Vérifie la connexion au transporteur
const verifyTransporter = async () => {
  try {
    await transporter.verify();
    return true;
  } catch (error) {
    logger.error('Erreur de vérification du transporteur', { error: error.message });
    return false;
  }
};

// Fonction pour générer un code à 6 chiffres
const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Fonction pour envoyer un email avec mécanisme de nouvelle tentative
const sendEmailWithRetry = async (mailOptions) => {
  try {
    // Vérifier la connexion
    const isConnected = await verifyTransporter();
    if (!isConnected) {
      resetTransporter();
      logger.info('Transporteur réinitialisé après échec de vérification');
    }
    
    // Envoyer l'email
    const info = await transporter.sendMail(mailOptions);
    retryCount = 0; // Réinitialiser le compteur en cas de succès
    return { success: true, messageId: info.messageId };
  } catch (error) {
    logger.error('Erreur d\'envoi d\'email', { 
      error: error.message, 
      email: mailOptions.to,
      retryCount 
    });
    
    // Gérer les erreurs de connexion spécifiques
    if (
      error.message.includes('Unexpected socket close') || 
      error.message.includes('Greeting never received') ||
      error.message.includes('ECONNRESET') ||
      error.message.includes('ETIMEDOUT')
    ) {
      if (retryCount < MAX_RETRIES) {
        retryCount++;
        logger.info(`Tentative de nouvelle connexion (${retryCount}/${MAX_RETRIES})`);
        resetTransporter();
        
        // Attendre un peu avant de réessayer
        await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
        return sendEmailWithRetry(mailOptions);
      }
    }
    
    return { success: false, error: error.message };
  }
};

// Envoi d'un code A2F
const sendVerificationCode = async (email, code) => {
  try {
    const mailOptions = {
      from: `"Service d'Authentification" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Votre code de vérification',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Code de vérification</h2>
          <p>Voici votre code de vérification à 6 chiffres:</p>
          <div style="font-size: 24px; font-weight: bold; background-color: #f0f0f0; padding: 10px; text-align: center; letter-spacing: 5px;">
            ${code}
          </div>
          <p>Ce code expirera dans 10 minutes.</p>
        </div>
      `,
      text: `Votre code de vérification est: ${code}. Ce code expirera dans 10 minutes.`
    };

    const result = await sendEmailWithRetry(mailOptions);
    
    if (result.success) {
      logger.info(`Email de vérification envoyé: ${result.messageId}`, { email });
      return true;
    } else {
      logger.error('Échec définitif d\'envoi d\'email', { email, error: result.error });
      return false;
    }
  } catch (error) {
    logger.error('Erreur inattendue lors de l\'envoi d\'email', { error: error.message, email });
    return false;
  }
};

// Envoi d'un lien de réinitialisation de mot de passe
const sendPasswordResetLink = async (email, token) => {
  const resetLink = `${process.env.APP_URL}/reset-password?token=${token}`;
  
  try {
    const mailOptions = {
      from: `"Service d'Authentification" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Réinitialisation de votre mot de passe',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Réinitialisation de mot de passe</h2>
          <p>Cliquez sur le lien ci-dessous pour réinitialiser votre mot de passe:</p>
          <p>
            <a href="${resetLink}" style="background-color: #4CAF50; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px; display: inline-block;">
              Réinitialiser mon mot de passe
            </a>
          </p>
          <p>Ce lien expirera dans 1 heure.</p>
        </div>
      `,
      text: `Pour réinitialiser votre mot de passe, cliquez sur ce lien: ${resetLink}. Ce lien expirera dans 1 heure.`
    };

    const result = await sendEmailWithRetry(mailOptions);
    
    if (result.success) {
      logger.info(`Email de réinitialisation envoyé: ${result.messageId}`, { email });
      return true;
    } else {
      logger.error('Échec définitif d\'envoi d\'email de réinitialisation', { email, error: result.error });
      return false;
    }
  } catch (error) {
    logger.error('Erreur inattendue lors de l\'envoi d\'email de réinitialisation', { error: error.message, email });
    return false;
  }
};

module.exports = {
  generateVerificationCode,
  sendVerificationCode,
  sendPasswordResetLink,
  verifyTransporter,
  resetTransporter
};