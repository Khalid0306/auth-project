const nodemailer = require('nodemailer');
require('dotenv').config(); // Assurez-vous d'avoir installé dotenv

// Configuration du logger simple pour le débogage
const debugLogger = {
  info: (message, meta = {}) => console.log(`[INFO] ${message}`, meta),
  error: (message, meta = {}) => console.error(`[ERROR] ${message}`, meta),
  debug: (message, meta = {}) => console.log(`[DEBUG] ${message}`, meta)
};

// Fonction qui teste différentes configurations SMTP
async function diagnosticSMTP() {
  console.log('=== DIAGNOSTIC DE CONFIGURATION SMTP ===');
  
  // 1. Vérifier les variables d'environnement
  console.log('\n[ÉTAPE 1] Vérification des variables d\'environnement');
  const host = process.env.EMAIL_HOST || 'smtp.gmail.com';
  const port = parseInt(process.env.EMAIL_PORT) || 587;
  const secure = process.env.EMAIL_SECURE === 'true';
  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASSWORD;
  
  console.log(`Host: ${host}`);
  console.log(`Port: ${port}`);
  console.log(`Secure: ${secure}`);
  console.log(`User: ${user ? user : '[NON DÉFINI]'}`);
  console.log(`Password: ${pass ? '[DÉFINI]' : '[NON DÉFINI]'}`);
  
  if (!user || !pass) {
    console.error('ERREUR: Variables d\'environnement EMAIL_USER ou EMAIL_PASSWORD non définies.');
    return;
  }

  // 2. Test avec configuration de base
  console.log('\n[ÉTAPE 2] Test avec configuration de base');
  await testSMTPConfig({
    host,
    port,
    secure,
    auth: { user, pass }
  });
  
  // 3. Test avec timeouts augmentés
  console.log('\n[ÉTAPE 3] Test avec timeouts augmentés');
  await testSMTPConfig({
    host,
    port,
    secure,
    auth: { user, pass },
    connectionTimeout: 20000,
    greetingTimeout: 20000,
    socketTimeout: 30000
  });
  
  // 4. Test avec port sécurisé (465)
  console.log('\n[ÉTAPE 4] Test avec port sécurisé (465)');
  await testSMTPConfig({
    host,
    port: 465,
    secure: true,
    auth: { user, pass },
    connectionTimeout: 20000,
    greetingTimeout: 20000,
    socketTimeout: 30000
  });
  
  // 5. Test avec autre configuration (TLS explicite)
  console.log('\n[ÉTAPE 5] Test avec TLS explicite');
  await testSMTPConfig({
    host,
    port,
    secure: false,
    auth: { user, pass },
    requireTLS: true,
    tls: {
      rejectUnauthorized: false
    }
  });
  
  console.log('\n=== DIAGNOSTIC TERMINÉ ===');
  console.log('Si aucune configuration ne fonctionne, vérifiez:');
  console.log('1. Les paramètres de sécurité de votre compte Google (validation en deux étapes + mot de passe d\'application)');
  console.log('2. La connectivité réseau vers les serveurs Gmail');
  console.log('3. Tout paramètre de pare-feu bloquant les connexions SMTP sortantes');
}

// Fonction qui teste une configuration spécifique
async function testSMTPConfig(config) {
  try {
    console.log(`Testing config: ${JSON.stringify({ ...config, auth: { user: config.auth.user, pass: '***' } })}`);
    
    // Activer le debug
    const fullConfig = {
      ...config,
      debug: true,
      logger: true
    };
    
    const transporter = nodemailer.createTransport(fullConfig);
    
    // Vérifier la connexion
    console.log('Vérification de la connexion...');
    await transporter.verify();
    console.log('✅ Connexion réussie!');
    
    // Tenter d'envoyer un email test
    console.log('Tentative d\'envoi d\'email test...');
    const testResult = await transporter.sendMail({
      from: `"Test Diagnostic" <${config.auth.user}>`,
      to: config.auth.user, // Envoyer à soi-même pour tester
      subject: "Test SMTP Diagnostic",
      text: "Ceci est un test de diagnostic SMTP. Si vous recevez cet email, la configuration fonctionne correctement!"
    });
    
    console.log(`✅ Email test envoyé avec succès! ID: ${testResult.messageId}`);
    return true;
  } catch (error) {
    console.error(`❌ Échec avec cette configuration: ${error.message}`);
    if (error.stack) {
      console.error('Détails de l\'erreur:', error.stack);
    }
    return false;
  }
}

// Fonction qui teste si on peut accéder au serveur
async function testNetworkConnectivity() {
  console.log('\n[TEST RÉSEAU] Vérification de la connectivité...');
  const net = require('net');
  const hosts = [
    { host: 'smtp.gmail.com', port: 587 },
    { host: 'smtp.gmail.com', port: 465 },
    { host: 'smtp.gmail.com', port: 25 }
  ];
  
  for (const { host, port } of hosts) {
    try {
      await new Promise((resolve, reject) => {
        const socket = net.createConnection(port, host);
        
        socket.setTimeout(5000);
        
        socket.on('connect', () => {
          console.log(`✅ Connexion réussie à ${host}:${port}`);
          socket.end();
          resolve();
        });
        
        socket.on('timeout', () => {
          console.error(`❌ Timeout en essayant de se connecter à ${host}:${port}`);
          socket.destroy();
          reject(new Error('Timeout'));
        });
        
        socket.on('error', (err) => {
          console.error(`❌ Erreur en essayant de se connecter à ${host}:${port}: ${err.message}`);
          reject(err);
        });
      });
    } catch (error) {
      // Déjà géré dans les gestionnaires d'événements
    }
  }
}

// Exécuter tous les tests
async function runAllDiagnostics() {
  console.log('======================================');
  console.log('DIAGNOSTIC COMPLET DE L\'ENVOI D\'EMAIL');
  console.log('======================================');
  
  await testNetworkConnectivity();
  await diagnosticSMTP();
  
  console.log('\nRECOMMANDATIONS:');
  console.log('1. Utilisez le code amélioré fourni précédemment avec les timeouts');
  console.log('2. Vérifiez que vous utilisez un mot de passe d\'application et non votre mot de passe Gmail normal');
  console.log('3. Essayez d\'utiliser un autre réseau (parfois les réseaux d\'entreprise bloquent SMTP)');
}

runAllDiagnostics().catch(console.error);