const express = require('express');
const router = express.Router();
const session = require('express-session');
const { authenticate } = require('../utils/auth');
const { logToDB } = require('../utils/logger');
const { log } = require('winston');
const authController = require('../controllers/authController');

router.get('/', (req, res) => {
  res.render('welcome', { 
    title: 'Accueil',
    user: req.session.user
    
  });
});

router.get('/register', (req, res) => {
  res.render('register', { title: 'Inscription', error: null });
});

router.get('/logout', authController.logout);
router.get('/verify-code', authController.showVerifyCodePage);
router.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { 
    error: null,
    success: null,
    email: ''
  });
});

router.post('/test', authController.resendVerificationCode);
router.get('/reset-password', authController.showResetPassword);

router.get('/login', (req, res) => {
  const registered = req.query.registered === 'true';
  res.render('login', { 
    title: 'Connexion', 
    error: null,
    success: registered ? 'Inscription réussie ! Vous pouvez maintenant vous connecter.' : null
  });
});


module.exports = router;
