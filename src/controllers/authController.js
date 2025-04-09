const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const { logToDB } = require('../utils/logger');
const { generateVerificationCode, sendVerificationCode, sendPasswordResetLink } = require('../utils/mailer');

// Fonction prévention injection SQL
const escapeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input
    .replace(/'/g, "''") // Échapper les apostrophes
    .replace(/\\/g, "\\\\"); // Échapper les backslashes
};

// Inscription
exports.register = (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validation du mot de passe 
    if (password.length < 8) {
      return res.status(400).render('register', { 
        error: 'Le mot de passe doit contenir au moins 8 caractères',
        username,
        email
      });
    }
    
    // Vérifier si l'utilisateur existe déjà
    db.get(
      `SELECT id FROM users WHERE username = ? OR email = ?`, 
      [escapeInput(username), escapeInput(email)], 
      async (err, user) => {
        if (err) {
          logToDB(null, 'REGISTER_ERROR', req.ip, req.headers['user-agent'], { error: err.message });
          return res.status(500).render('register', { 
            error: 'Erreur serveur, veuillez réessayer',
            username,
            email
          });
        }
        
        if (user) {
          return res.status(400).render('register', { 
            error: 'Nom d\'utilisateur ou email déjà utilisé',
            username,
            email
          });
        }
        
        // Hasher le mot de passe
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(
          `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
          [escapeInput(username), escapeInput(email), hashedPassword],
          function(err) {
            if (err) {
              logToDB(null, 'REGISTER_ERROR', req.ip, req.headers['user-agent'], { error: err.message });
              return res.status(500).render('register', { 
                error: 'Erreur lors de la création du compte',
                username,
                email
              });
            }
            
            const userId = this.lastID;
            
            // Logger la création du compte
            logToDB(userId, 'USER_REGISTERED', req.ip, req.headers['user-agent'], { username, email });
            
            // Rediriger vers la connexion
            res.redirect('/login?registered=true');
          }
        );
      }
    );
  } catch (error) {
    logToDB(null, 'REGISTER_ERROR', req.ip, req.headers['user-agent'], { error: error.message });
    res.status(500).render('register', { 
      error: 'Une erreur est survenue, veuillez réessayer',
      username: req.body.username,
      email: req.body.email
    });
  }
};

// Connexion utilisateur
exports.login = (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Rechercher l'utilisateur
    db.get(
      `SELECT id, username, email, password FROM users WHERE username = ? OR email = ?`,
      [escapeInput(username), escapeInput(username)],
      async (err, user) => {
        if (err) {
          logToDB(null, 'LOGIN_ERROR', req.ip, req.headers['user-agent'], { error: err.message });
          return res.status(500).render('login', { 
            error: 'Erreur serveur, veuillez réessayer',
            username
          });
        }
        
        if (!user) {
          logToDB(null, 'LOGIN_FAILED', req.ip, req.headers['user-agent'], { username });
          return res.status(401).render('login', { 
            error: 'Identifiants incorrects',
            username
          });
        }
        
        // Vérifier le mot de passe
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
          logToDB(user.id, 'LOGIN_FAILED', req.ip, req.headers['user-agent'], { username });
          return res.status(401).render('login', { 
            error: 'Identifiants incorrects',
            username
          });
        }
        
        // Générer un code de vérification pour A2F
        const verificationCode = generateVerificationCode();
        const expiryTime = new Date();
        expiryTime.setMinutes(expiryTime.getMinutes() + 10); // Code valide 10 minutes
        
        // Enregistrer le code de vérification
        db.run(
          `INSERT INTO verification_codes (user_id, code, type, expires_at) VALUES (?, ?, ?, ?)`,
          [user.id, verificationCode, 'A2F', expiryTime.toISOString()],
          async (err) => {
            if (err) {
              logToDB(user.id, 'A2F_ERROR', req.ip, req.headers['user-agent'], { error: err.message });
              return res.status(500).render('login', { 
                error: 'Erreur lors de la génération du code de vérification',
                username
              });
            }
            
            // Envoyer le code par email
            const emailSent = await sendVerificationCode(user.email, verificationCode);
            
            if (!emailSent) {
              return res.status(500).render('login', { 
                error: 'Erreur lors de l\'envoi du code de vérification',
                username
              });
            }
            
            // Stocker l'ID utilisateur dans la session pour la vérification A2F
            req.session.userId = user.id;
            
            // Logger la tentative de connexion
            logToDB(user.id, 'LOGIN_A2F_SENT', req.ip, req.headers['user-agent']);
            
            // Rediriger vers la page de vérification A2F
            console.log("Redirection vers /verify-code en cours...");
            res.redirect(`/verify-code?userId=${user.id}`);
          }
        );
      }
    );
  } catch (error) {
    logToDB(null, 'LOGIN_ERROR', req.ip, req.headers['user-agent'], { error: error.message });
    res.status(500).render('login', { 
      error: 'Une erreur est survenue, veuillez réessayer',
      username: req.body.username
    });
  }
};

// Afficher le formulaire de vérification
exports.showVerifyCodePage = (req, res) => {
  console.log("Fonction showVerifyCodePage appelée");
  
  const userId = req.session.userId || req.query.userId;
  
  if (!userId) {
    return res.redirect('/login');
  }
  
  res.render('verify-code', { 
    error: null,
    userId
  });
};

// Vérification du code A2F
exports.verifyCode = (req, res) => {
  try {
    const { code } = req.body;
    const { userId } = req.session;
    
    if (!userId) {
      return res.redirect('/login');
    }
    
    if (!code || code.length !== 6) {
      return res.status(400).render('verify-code', { 
        error: 'Code invalide',
        userId
      });
    }
    
    // Vérifier le code
    db.get(
      `SELECT id FROM verification_codes 
       WHERE user_id = ? AND code = ? AND type = 'A2F' AND expires_at > datetime('now')
       ORDER BY created_at DESC LIMIT 1`,
      [userId, code],
      (err, verificationRecord) => {
        if (err) {
          logToDB(userId, 'A2F_VERIFY_ERROR', req.ip, req.headers['user-agent'], { error: err.message });
          return res.status(500).render('verify-code', { 
            error: 'Erreur serveur, veuillez réessayer',
            userId
          });
        }
        
        if (!verificationRecord) {
          logToDB(userId, 'A2F_VERIFY_FAILED', req.ip, req.headers['user-agent']);
          return res.status(401).render('verify-code', { 
            error: 'Code incorrect ou expiré',
            userId
          });
        }
        
        // Supprimer le code utilisé
        db.run(
          `DELETE FROM verification_codes WHERE id = ?`,
          [verificationRecord.id]
        );
        
        // Récupérer les infos utilisateur pour le JWT
        db.get(
          `SELECT id, username, email FROM users WHERE id = ?`,
          [userId],
          (err, user) => {
            if (err || !user) {
              return res.redirect('/login');
            }
            
            // Création du token JWT
            const token = jwt.sign(
              { id: user.id, username: user.username, email: user.email },
              process.env.JWT_SECRET,
              { expiresIn: '1h' }
            );
            
            // Enregistrer la session dans la BDD
            const expiryTime = new Date();
            expiryTime.setHours(expiryTime.getHours() + 1); // Session d'une heure
            
            db.run(
              `INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)`,
              [user.id, token, expiryTime.toISOString()],
              (err) => {
                if (err) {
                  logToDB(user.id, 'SESSION_CREATE_ERROR', req.ip, req.headers['user-agent'], { error: err.message });
                  return res.redirect('/login');
                }
                
                // Définir le cookie de session
                res.cookie('token', token, {
                  httpOnly: true,
                  secure: false,
                  maxAge: 3600000 // 1 heure
                });
                
                // Marquer la session comme vérifiée pour 2FA
                req.session.twoFactorVerified = true;
                
                // Logger la connexion réussie
                logToDB(user.id, 'LOGIN_SUCCESS', req.ip, req.headers['user-agent']);
                
                // Rediriger vers la page d'accueil
                res.redirect('/');
              }
            );
          }
        );
      }
    );
  } catch (error) {
    const userId = req.session.userId;
    logToDB(userId, 'A2F_VERIFY_ERROR', req.ip, req.headers['user-agent'], { error: error.message });
    res.status(500).render('verify-code', { 
      error: 'Une erreur est survenue, veuillez réessayer',
      userId
    });
  }
};


// Demande de réinitialisation de mot de passe
exports.forgotPassword = (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).render('forgot-password', { 
        error: 'Email requis'
      });
    }
    
    // Vérifier si l'utilisateur existe
    db.get(
      `SELECT id, email FROM users WHERE email = ?`,
      [escapeInput(email)],
      async (err, user) => {
        if (err) {
          logToDB(null, 'PASSWORD_RESET_ERROR', req.ip, req.headers['user-agent'], { error: err.message, email });
          return res.status(500).render('forgot-password', { 
            error: 'Erreur serveur, veuillez réessayer',
            email
          });
        }
        
        // Même si l'utilisateur n'existe pas, ne pas l'indiquer
        if (!user) {
          setTimeout(() => {
            res.render('forgot-password', { 
              success: 'Si cette adresse email existe dans notre système, vous recevrez un lien de réinitialisation'
            });
          }, 1000);
          return;
        }
        
        // Générer un token JWT pour la réinitialisation
        const resetToken = jwt.sign(
          { id: user.id, purpose: 'password_reset' },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        );
        
        // Enregistrer le token dans la base de données
        const expiryTime = new Date();
        expiryTime.setHours(expiryTime.getHours() + 1);
        
        db.run(
          `INSERT INTO verification_codes (user_id, code, type, expires_at) VALUES (?, ?, ?, ?)`,
          [user.id, resetToken, 'PASSWORD_RESET', expiryTime.toISOString()],
          async (err) => {
            if (err) {
              logToDB(user.id, 'PASSWORD_RESET_ERROR', req.ip, req.headers['user-agent'], { error: err.message });
              return res.status(500).render('forgot-password', { 
                error: 'Erreur lors de la génération du lien de réinitialisation',
                email
              });
            }
            
            // Envoyer l'email de réinitialisation
            const emailSent = await sendPasswordResetLink(user.email, resetToken);
            
            if (!emailSent) {
              return res.status(500).render('forgot-password', { 
                error: 'Erreur lors de l\'envoi de l\'email de réinitialisation',
                email
              });
            }
            
            // Logger la demande de réinitialisation
            logToDB(user.id, 'PASSWORD_RESET_REQUESTED', req.ip, req.headers['user-agent']);
            
            res.render('forgot-password', { 
              success: 'Un lien de réinitialisation a été envoyé à votre adresse email'
            });
          }
        );
      }
    );
  } catch (error) {
    logToDB(null, 'PASSWORD_RESET_ERROR', req.ip, req.headers['user-agent'], { error: error.message });
    res.status(500).render('forgot-password', { 
      error: 'Une erreur est survenue, veuillez réessayer',
      email: req.body.email
    });
  }
};

// Réinitialisation de mot de passe
exports.resetPassword = (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;
    
    if (!token) {
      return res.redirect('/forgot-password');
    }
    
    if (password !== confirmPassword) {
      return res.status(400).render('reset-password', { 
        error: 'Les mots de passe ne correspondent pas',
        token
      });
    }
    
    if (password.length < 8) {
      return res.status(400).render('reset-password', { 
        error: 'Le mot de passe doit contenir au moins 8 caractères',
        token
      });
    }
    
    // Vérifier le token
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      if (decoded.purpose !== 'password_reset') {
        return res.status(400).redirect('/forgot-password');
      }
      
      // Vérifier si le token existe dans la BDD
      db.get(
        `SELECT id FROM verification_codes 
         WHERE user_id = ? AND code = ? AND type = 'PASSWORD_RESET' AND expires_at > datetime('now')`,
        [decoded.id, token],
        async (err, verificationRecord) => {
          if (err || !verificationRecord) {
            return res.status(400).render('reset-password', { 
              error: 'Lien de réinitialisation invalide ou expiré',
              token
            });
          }
          
          // Hasher le nouveau mot de passe
          const hashedPassword = await bcrypt.hash(password, 10);
          
          // Mettre à jour le mot de passe
          db.run(
            `UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?`,
            [hashedPassword, decoded.id],
            function(err) {
              if (err) {
                logToDB(decoded.id, 'PASSWORD_RESET_ERROR', req.ip, req.headers['user-agent'], { error: err.message });
                return res.status(500).render('reset-password', { 
                  error: 'Erreur lors de la mise à jour du mot de passe',
                  token
                });
              }
              
              // Supprimer le token utilisé
              db.run(
                `DELETE FROM verification_codes WHERE id = ?`,
                [verificationRecord.id]
              );
              
              // Logger la réinitialisation réussie
              logToDB(decoded.id, 'PASSWORD_RESET_SUCCESS', req.ip, req.headers['user-agent']);
              
              res.redirect('/login?reset=true');
            }
          );
        }
      );
    } catch (error) {
      return res.status(400).render('reset-password', { 
        error: 'Lien de réinitialisation invalide',
        token
      });
    }
  } catch (error) {
    logToDB(null, 'PASSWORD_RESET_ERROR', req.ip, req.headers['user-agent'], { error: error.message });
    res.status(500).render('reset-password', { 
      error: 'Une erreur est survenue, veuillez réessayer',
      token: req.body.token
    });
  }
};

// Afficher la page de réinitialisation de mot de passe
exports.showResetPassword = (req, res) => {
  try {
    const token = req.query.token;
    
    if (!token) {
      // Si aucun token n'est fourni, rediriger vers la page de récupération de mot de passe
      return res.redirect('/forgot-password?error=Token+de+réinitialisation+manquant');
    }

    res.render('reset-password', {
      token: token
    });

  } catch (error) {
    res.redirect('/forgot-password?error=Une+erreur+est+survenue');
  }
};

// Déconnexion utilisateur
exports.logout = (req, res) => {
  try {
    const token = req.cookies.token;
    
    if (!token) {
      return res.redirect('/login');
    }
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Invalider le token dans la base de données
      db.run(
        `DELETE FROM sessions WHERE user_id = ? AND token = ?`,
        [decoded.id, token],
        (err) => {
          if (err) {
            logToDB(decoded.id, 'LOGOUT_ERROR', req.ip, req.headers['user-agent'], { error: err.message });
          } else {
            logToDB(decoded.id, 'LOGOUT_SUCCESS', req.ip, req.headers['user-agent']);
          }
          
          // Supprimer le cookie
          res.clearCookie('token');
          
          // Détruire la session
          req.session.destroy();
          
          res.redirect('/login?logout=true');
        }
      );
    } catch (error) {
      // Si le token est invalide, simplement déconnecter
      res.clearCookie('token');
      req.session.destroy();
      res.redirect('/login');
    }
  } catch (error) {
    logToDB(null, 'LOGOUT_ERROR', req.ip, req.headers['user-agent'], { error: error.message });
    res.clearCookie('token');
    req.session.destroy();
    res.redirect('/login');
  }
};

// Envoyer un nouveau code de vérification
exports.resendVerificationCode = async (req, res) => {
  console.log("test lancement");
  
  try {
    const userId = req.session.userId || req.query.userId;
    
    if (!userId) {
      return res.redirect('/login');
    }
    
    // Obtenir l'email de l'utilisateur
    db.get(
      `SELECT email FROM users WHERE id = ?`,
      [userId],
      async (err, user) => {
        if (err || !user) {
          return res.status(400).render('verify-code', {
            error: 'Utilisateur non trouvé',
            userId
          });
        }
        
        // Générer un nouveau code
        const verificationCode = generateVerificationCode();
        const expiryTime = new Date();
        expiryTime.setMinutes(expiryTime.getMinutes() + 10);
        
        // Enregistrer le nouveau code
        db.run(
          `INSERT INTO verification_codes (user_id, code, type, expires_at) VALUES (?, ?, ?, ?)`,
          [userId, verificationCode, 'A2F', expiryTime.toISOString()],
          async (err) => {
            if (err) {
              logToDB(userId, 'A2F_RESEND_ERROR', req.ip, req.headers['user-agent'], { error: err.message });
              return res.status(500).render('verify-code', {
                error: 'Erreur lors de la génération du code de vérification',
                userId
              });
            }
            
            // Envoyer le code par email
            const emailSent = await sendVerificationCode(user.email, verificationCode);
            
            if (!emailSent) {
              return res.status(500).render('verify-code', {
                error: 'Erreur lors de l\'envoi du code de vérification',
                userId
              });
            }
            
            // Logger l'envoi du nouveau code
            logToDB(userId, 'A2F_RESEND_SUCCESS', req.ip, req.headers['user-agent']);
            
            res.render('verify-code', {
              success: 'Un nouveau code de vérification a été envoyé à votre adresse email',
              userId
            });
          }
        );
      }
    );
  } catch (error) {
    const userId = req.session.userId;
    logToDB(userId, 'A2F_RESEND_ERROR', req.ip, req.headers['user-agent'], { error: error.message });
    res.status(500).render('verify-code', {
      error: 'Une erreur est survenue, veuillez réessayer',
      userId
    });
  }
};
