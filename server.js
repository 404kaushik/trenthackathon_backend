const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');

const app = express();
const port = 5001;

// Middleware
app.use(cors());
app.use(express.json());

app.use(cors({
  origin: ['https://trenthackathon.vercel.app/', 'https://hacktrent.ca/', 'http://localhost:3000' ], // or '*'
  methods: ['GET', 'POST', 'PUT', 'DELETE'],  // Allowed HTTP methods
  allowedHeaders: ['Content-Type', 'Authorization'],  // Allowed request headers
  credentials: true,
}));

// Connect to PostgreSQL
const pool = new Pool({
  connectionString: 'postgresql://hacktrent_user:GRE8NV8Etg5CvgMWys7D9yaDPyACLRGW@dpg-cs5o0l08fa8c73aoa4d0-a.oregon-postgres.render.com/hacktrent',
  ssl: {
    rejectUnauthorized: false,  // This disables certificate validation, which is fine for testing
  }
});


// JWT Secret
const JWT_SECRET = '12345@6';  // replace with a strong secret

 
// Configure multer for file upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });


// Routes
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if user already exists
    const userExist = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (userExist.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into DB
    const newUser = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
      [name, email, hashedPassword]
    );

    res.status(201).json(newUser.rows[0]);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.get('/api/test', (req, res) => {
  res.json({ message: 'Hello from the backend!' });
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ id: user.rows[0].id, role: user.rows[0].role }, JWT_SECRET, { expiresIn: '24h' });
    console.log(token);

    res.json({ token, user: { id: user.rows[0].id, name: user.rows[0].name, role: user.rows[0].role } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.get('/users', async (req, res) => {
  try {
    const users = await pool.query('SELECT * FROM users');
    res.json(users.rows);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.get('/profile', async (req, res) => {
  const authHeader = req.headers.authorization;
  
  // Check if the authorization header exists
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided or token is not properly formatted' });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);

    if (user.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ user: user.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.post('/apply', upload.single('resume'), async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  const {
    first_name,
    last_name,
    email,
    age,
    gender,
    pronouns,
    race,
    school,
    major,
    level_of_study,
    country_of_residence,
    question1,
    question2,
    tshirt_size,
    dietary_restrictions,
    agree_conduct,
    share_info,
    receive_emails,
    share_resume
  } = req.body;

  let resume_url = null;
  if (req.file) {
    resume_url = `http://localhost:5001/uploads/${req.file.filename}`;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Insert application into the database
    const newApplication = await pool.query(
      `INSERT INTO applications (
        user_id, first_name, last_name, email, age, gender, pronouns, race, school, major, 
        level_of_study, country_of_residence, question1, question2, tshirt_size, dietary_restrictions, 
        agree_conduct, share_info, receive_emails, resume_url, share_resume
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
      ) RETURNING *`,
      [
        decoded.id, first_name, last_name, email, age, gender, pronouns, race, school, major,
        level_of_study, country_of_residence, question1, question2, tshirt_size, dietary_restrictions,
        agree_conduct, share_info, receive_emails, resume_url, share_resume
      ]
    );

    res.status(201).json({ message: "Application submitted", application: newApplication.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/dashboard', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided or token is not properly formatted' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Decoded Token ID:', decoded.id);

    const user = await pool.query('SELECT name, application_status FROM users WHERE id = $1', [decoded.id]);

    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ user: user.rows[0] });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    console.error('Error in /dashboard:', err);
    res.status(500).json({ message: 'Failed to load dashboard' });
  }
});


app.post('/submit-application', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Safely extract token from headers

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET); // Verify the token
    const userId = decoded.id;

    // Check if the user already has their application status as 'In Review'
    const user = await pool.query('SELECT application_status FROM users WHERE id = $1', [userId]);
    
    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Prevent re-submission if the application status is already 'In Review' or 'Accepted'
    if (user.rows[0].application_status === 'In Review' || user.rows[0].application_status === 'Accepted') {
      return res.status(400).json({ message: 'Application already submitted' });
    }

    // Extract application details from request body
    const {
      first_name,
      last_name,
      email,
      age,
      gender,
      pronouns,
      race,
      school,
      major,
      level_of_study,
      country_of_residence,
      phonenumber,  // Add phonenumber to the request body
      question1,
      question2,
      tshirt_size,
      dietary_restrictions,
      agree_conduct,
      share_info,
      resume_url,
      receive_emails,
      share_resume
    } = req.body;

    // Validate dietary_restrictions to ensure it's an array
    const dietaryRestrictions = Array.isArray(dietary_restrictions) ? dietary_restrictions.join(',') : '';

    // Insert application into the database
    const newApplication = await pool.query(
      `INSERT INTO applications (
        user_id, first_name, last_name, email, age, gender, pronouns, race, school, major, 
        level_of_study, country_of_residence, phonenumber, question1, question2, tshirt_size, 
        dietary_restrictions, agree_conduct, share_info, resume_url, receive_emails, share_resume
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
      ) RETURNING *`,
      [
        userId, first_name, last_name, email, age, gender, pronouns, race, school, major,
        level_of_study, country_of_residence, phonenumber, question1, question2, tshirt_size,
        dietaryRestrictions, agree_conduct, share_info, resume_url, receive_emails, share_resume
      ]
    );

    // Update the user's application status to 'In Review'
    await pool.query('UPDATE users SET application_status = $1 WHERE id = $2', ['In Review', userId]);

    // Send final response with success message and new application details
    res.status(201).json({ 
      message: "Application submitted successfully", 
      application: newApplication.rows[0] 
    });

  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    console.error('Error submitting application:', err);
    res.status(500).json({ error: 'Failed to submit application.' });
  }
});




// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});