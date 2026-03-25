const Datastore = require('nedb');
const path = require('path');
const bcrypt = require('bcryptjs');

const db = new Datastore({
  filename: path.join(__dirname, 'users.db'),
  autoload: true
});

setTimeout(() => {
  db.findOne({ email: 'admin@trading-ia.com' }, function(err, user) {
    if (!user) {
      bcrypt.hash('Admin2024!', 10, function(err, hash) {
        db.insert({
          email: 'admin@trading-ia.com',
          password: hash,
          name: 'Admin',
          role: 'admin',
          verified: true,
          analysisCount: 0,
          subscribed: true,
          createdAt: new Date()
        }, function() {
          console.log('✅ Admin créé: admin@trading-ia.com / Admin2024!');
        });
      });
    } else {
      console.log('✅ Admin déjà existant');
    }
  });
}, 1000);

module.exports = db;