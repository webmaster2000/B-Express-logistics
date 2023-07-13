const express = require('express');
const morgan = require('morgan');
require('dotenv').config();
const bodyParser = require('body-parser');
const cors = require('cors');
const uuid = require('uuid');
const db = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// create express app
const app = express();
const nodemailer = require('nodemailer');
const PORT = process.env.PORT || 3000;

// middlewares
app.use(morgan('dev'));
app.use(bodyParser.json());

app.use(bodyParser.urlencoded({ extended: true }))



app.use(cors({
  origin: ["http://127.0.0.1:5500"],
  credentials: true
}));

app.use((req, res, next) => {
  console.log('Entered');
  next();
});

app.post('/signup', async (req, res) => {
  const { first_name, last_name, email, password } = req.body;

  try {
    if (!first_name) throw Error('Insert your first name');

    // Query the database to check if the email exists
    const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
    const token = jwt.sign({ email }, 'your-secret-key', { expiresIn: '1h' });

    if (rows.length > 0) {
      // Email already exists in the database
      res.status(400).json({ error: 'Email already exists. Please use a different email address.' });
      return;
    }

    // Generate id using uuid.v4()
    const id = uuid.v4();

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const sql = `INSERT INTO users(id, first_name, last_name, email, password)
               VALUES (?, ?, ?, ?, ?)`;

    await db.execute(sql, [id, first_name, last_name, email, hash]);

    res.status(201).json({ message: 'Your request has been recorded. We will get back to you soon!', token });

  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/check-email', async (req, res) => {
  const { email } = req.body;

  try {
    // Query the database to check if the email exists
    const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);

    if (rows.length > 0) {
      // Email exists in the database
      res.json({ exists: true });
    } else {
      // Email doesn't exist in the database
      res.json({ exists: false });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});




app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

    if (rows.length === 0) {
      res.status(400).json({ error: 'Invalid email or password. Please try again.' });
      return;
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      res.status(400).json({ error: 'Invalid email or password. Please try again.' });
      return;
    }

    // Generate a token
    const token = jwt.sign({ userId: user.id, email: user.email,firstName: user.first_name, lastName:user.last_name }, 'your-secret-key', { expiresIn: '1h' });

    // Successful login, return the token
    res.status(200).json({ token: token, id: user.id, email: user.email, firstName: user.first_name, lastName: user.last_name });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Middleware to verify the token
function verifyToken(req, res, next) {
  // Get the token from the query parameters or headers
  const token = req.query.token || req.headers.authorization?.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Unauthorized. Missing token.' });
    return;
  }

  // Verify the token
  jwt.verify(token, 'your-secret-key', (error, decoded) => {
    if (error) {
      res.status(401).json({ error: 'Unauthorized. Invalid token.' });
      return;
    }

    // Token is valid, add the decoded payload to the request object
    req.user = decoded;
    next();
  });
}

// Protected route example
app.get('/home.html', verifyToken, (req, res) => {
  // Token is verified, extract user information from the payload
  const { userId, email } = req.user;

  // Process the protected route logic here
  // Return the home page content or perform other actions

  res.status(200).send(`Welcome to the homepage, user ${userId}. email: ${email}`);
});




app.patch('/', async (req, res) => {
  const { email, password } = req.body;

  try {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    let sql = `SELECT * FROM users WHERE email = ?`;
    const [rows] = await db.execute(sql, [email]);

    if (rows.length === 0) {
      // Email doesn't exist in the database
      res.status(400).json({ error: 'Email not found. Please enter a valid email address.' });
      return;
    }

    // Update the password for the existing user
    sql = `UPDATE users SET password = ? WHERE email = ?`;
    await db.execute(sql, [hash, email]);

    res.status(200).json({ message: 'Password updated successfully.' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});





// Handle form submission
app.post('/submit', (req, res) => {
  const formData = req.body;
  if (!isValidFormData(formData)) {
    res.status(400).send('Invalid form data');
    return;
  }

  // Generate a confirmation code
  const confirmationCode = generateConfirmationCode();

  // Send confirmation email with the code
  sendConfirmationEmail(formData.email, confirmationCode, (error) => {
    if (error) {
      console.error('Error sending confirmation email:', error);
      res.status(500).send('Internal server error');
    } else {
      res.status(200).send('Form submitted successfully');
    }
  });
});


// Server-side JavaScript code
app.get('/user/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const user = await db.execute('SELECT * FROM users WHERE id = ?', [id]);

    if (user[0].length === 0) {
      throw new Error('User not found.');
    }

    const { first_name, last_name, email } = user[0][0];

    res.status(200).json({ id, first_name, last_name, email });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});






// Validation and email code as before

app.listen(PORT, () => {
  console.log(`Listening on PORT ${PORT}`);
});
