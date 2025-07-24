const bcrypt = require('bcryptjs');

const password = 'Howaradas12A@'; // Replace with your desired password
bcrypt.hash(password, 10, (err, hash) => {
  if (err) console.error('Error hashing password:', err);
  console.log('Hashed Password:', hash);
});
