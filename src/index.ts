import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import zod from 'zod';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import 'dotenv/config';

// TODO: use firebase for auth or an alternative managing passwords locally is just a bad idea
// TODO: use an orm for increased security
// TODO: authentication as a middleware
// TODO: use zod or an alternative for cross server client type safety.
// Schemas
const nameSchema = zod.string().min(1).max(50);
const emailSchema = zod.string().email().min(1).max(50);
const passwordSchema = zod.string().min(8).max(50);
const userSchema = zod.object({
  id: zod.number(),
  email: zod.string().email(),
  name: zod.string(),
  password: zod.string(),
  // TODO: This is never appended to the database???
  role: zod.string().optional(),
  application_status: zod.string().optional(),
});
// Error enum
enum ServerError {
  Generic = 'Generic',
  UserExists = 'UserExists',
  InvalidCredentials = 'InvalidCredentials',
  UserNotFound = 'UserNotFound',
  ApplicationAlreadySubmitted = 'ApplicationAlreadySubmitted',
}
// Read Constants
const SALT_ROUNDS = 10;
const PORT = process.env.PORT ?? 3000;
const DB_URL = process.env.DB_URL;
if (DB_URL == undefined) throw new Error('DB_URL is not defined');
const JWT_SECRET = process.env.JWT_SECRET;
if (JWT_SECRET == undefined) throw new Error('JWT_SECRET is not defined');
// Connect to PostgreSQL
// TODO: Use an orm for increased security
const pool = new Pool({
  connectionString: DB_URL,
  ssl: {
    rejectUnauthorized: true, // This disables certificate validation, which is fine for testing
  },
});
// Setup Express
const app = express();
app.use(helmet());
app.use(
  cors({
    origin: [
      'https://trenthackathon.vercel.app/',
      'https://hacktrent.ca/',
      'http://localhost:3000',
    ], // or '*'
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allowed HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Allowed request headers
    credentials: true,
  })
);

app.use(express.json());

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
  },
});

const upload = multer({ storage: storage });

// TODO: It would be good if we applied this to to the object when signing for better round trips
const jwtPayload = zod.object({
  id: zod.number(),
  role: zod.string(),
});
type PossibleUser =
  | { error: false; user: zod.infer<typeof userSchema> }
  | { error: true; code: number; message: string; type: ServerError };
const getUser = async (
  authHeader: string | undefined
): Promise<PossibleUser> => {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      error: true,
      code: 401,
      message: 'No token provided or token is not properly formatted',
      type: ServerError.InvalidCredentials,
    };
  }
  const token = authHeader.split(' ')[1];
  try {
    const tokenPayload = jwt.verify(token, JWT_SECRET);
    const parsedPayload = jwtPayload.safeParse(tokenPayload);
    if (!parsedPayload.success) {
      return {
        error: true,
        code: 500,
        message: 'Internal server error',
        type: ServerError.InvalidCredentials,
      };
    }
    const payload = parsedPayload.data;
    const userTable = await pool.query('SELECT * FROM users WHERE id = $1', [
      payload.id,
    ]);
    if (userTable.rows.length <= 0) {
      // Note: This should be impossible, given the token came from the server when we added to the database
      return {
        error: true,
        code: 404,
        message: 'User not found',
        type: ServerError.UserNotFound,
      };
    }
    const rawUser = userSchema.safeParse(userTable.rows[0]);
    if (!rawUser.success) {
      return {
        error: true,
        code: 500,
        message: 'Internal server error',
        type: ServerError.Generic,
      };
    }
    return {
      error: false,
      user: rawUser.data,
    };
  } catch (err) {
    // TODO: Make this type safe
    // @ts-ignore
    if (err.name === 'TokenExpiredError') {
      return {
        error: true,
        code: 401,
        message: 'Token expired',
        type: ServerError.InvalidCredentials,
      };
    } else {
      return {
        error: true,
        code: 500,
        message: 'Internal server error',
        type: ServerError.Generic,
      };
    }
  }
};
// API
app.get('/', (req, res) => {
  console.log('GET request to /');
  res.send('Trent API is running');
});
// /register - post request to register a new user
const registerSchema = zod.object({
  name: nameSchema,
  email: emailSchema,
  password: passwordSchema,
});
app.post('/register', async (req, res) => {
  console.log('Post request to /register');
  // TODO: Use firebase auth so we do not need to worry about password security so much.
  // Safely extract the email and password from the request body
  const requestBody = await registerSchema.safeParseAsync(req.body);
  if (!requestBody.success) {
    res
      .status(400)
      .json({ message: 'Invalid request body', type: ServerError.Generic });
    return;
  }
  const { name, email, password } = requestBody.data;
  // Ensure the desired user exists
  try {
    await pool.query('BEGIN');
    // Ensure the user exists
    // TODO: I think we should do this before the transaction as it does not cause mutation
    const userExist = await pool.query('SELECT * FROM users WHERE email = $1', [
      email,
    ]);
    if (userExist.rows.length > 0) {
      await pool.query('ROLLBACK');
      res
        .status(400)
        .json({ message: 'User already exists', type: ServerError.UserExists });
      return;
    }
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    // Insert user into DB
    await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id',
      [name, email, hashedPassword]
    );
    // Commit and return
    await pool.query('COMMIT');
    res.status(201).json({ message: 'User registered' });
  } catch (_) {
    // Note: We drop the error as to not leak any information about the process
    await pool.query('ROLLBACK');
    res
      .status(500)
      .json({ message: 'Internal server error', type: ServerError.Generic });
    return;
  }
});
// /login - post request to login a user
const loginSchema = zod.object({
  email: emailSchema,
  password: passwordSchema,
});
app.post('/login', async (req, res) => {
  console.log('Post request to /login');
  // TODO: Use firebase auth so we do not need to worry about password security so much.
  // Safely extract the email and password from the request body
  const requestBody = await loginSchema.safeParseAsync(req.body);
  if (!requestBody.success) {
    res
      .status(400)
      .json({ message: 'Invalid request body', type: ServerError.Generic });
    return;
  }
  const { email, password } = requestBody.data;
  // Perform login
  try {
    // Find user by email
    const userResult = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    if (userResult.rows.length <= 0) {
      res.status(400).json({
        message: 'Invalid credentials',
        type: ServerError.InvalidCredentials,
      });
      return;
    }
    // TODO: using an orm would be better
    const userTable = userResult.rows[0];
    const validUser = userSchema.safeParse(userTable);
    if (!validUser.success) {
      res
        .status(500)
        .json({ message: 'Internal server error', type: ServerError.Generic });
      return;
    }
    const user = validUser.data;
    // Check password
    // Compare passwords
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      res.status(400).json({
        message: 'Invalid credentials',
        type: ServerError.InvalidCredentials,
      });
      return;
    }
    // Generate JWST
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: '24h',
    });
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
      },
    });
    return;
  } catch (_) {
    // Note: We drop the error as to not leak any information about the process
    res
      .status(500)
      .json({ message: 'Internal server error', type: ServerError.Generic });
    return;
  }
});
// Note: I removed this route as it was completely unsecure
// /users - get request to get all users
// /profile - get request to get a user's profile
app.post('/profile', async (req, res) => {
  console.log('Post request to /profile');
  try {
    const possibleUser = await getUser(req.headers.authorization);
    if (possibleUser.error) {
      res.status(possibleUser.code).json(possibleUser);
      return;
    }
    const user = possibleUser.user;
    // Note: we rebuild the user object to ensure we do not leak any information such as the password
    res.json({
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
      },
    });
    return;
  } catch (_) {
    res
      .status(500)
      .json({ message: 'Internal server error', type: ServerError.Generic });
    return;
  }
});
// /apply - post request to submit an application
const applySchema = zod.object({
  // TODO: Ensure types and improves restrictions
  first_name: zod.string(),
  last_name: zod.string(),
  email: emailSchema,
  age: zod.number(),
  gender: zod.string(),
  pronouns: zod.string(),
  race: zod.string(),
  school: zod.string(),
  major: zod.string(),
  level_of_study: zod.string(),
  country_of_residence: zod.string(),
  question1: zod.string(),
  question2: zod.string(),
  tshirt_size: zod.string(),
  dietary_restrictions: zod.string(),
  agree_conduct: zod.boolean(),
  share_info: zod.boolean(),
  receive_emails: zod.boolean(),
  share_resume: zod.boolean(),
});
app.post('/apply', upload.single('resume'), async (req, res) => {
  console.log('Post request to /apply');
  try {
    const possibleUser = await getUser(req.headers.authorization);
    if (possibleUser.error) {
      res.status(possibleUser.code).json(possibleUser);
      return;
    }
    const user = possibleUser.user;
    // Get Body Data
    const parsedBody = await applySchema.safeParseAsync(req.body);
    if (!parsedBody.success) {
      res
        .status(400)
        .json({ message: 'Invalid request body', type: ServerError.Generic });
      return;
    }
    const requestBody = parsedBody.data;
    // TODO: use a hash instead of the raw filename, collisions, data visibility
    const resume_url =
      req.file != undefined
        ? `http://localhost:5001/uploads/${req.file.filename}`
        : null;
    // TODO: Is there a way todo this in a non positional manner?
    const newApplication = await pool.query(
      `INSERT INTO applications (
        user_id, first_name, last_name, email, age, gender, pronouns, race, school, major, 
        level_of_study, country_of_residence, question1, question2, tshirt_size, dietary_restrictions, 
        agree_conduct, share_info, receive_emails, resume_url, share_resume
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
      ) RETURNING *`,
      [
        user.id,
        requestBody.first_name,
        requestBody.last_name,
        requestBody.email,
        requestBody.age,
        requestBody.gender,
        requestBody.pronouns,
        requestBody.race,
        requestBody.school,
        requestBody.major,
        requestBody.level_of_study,
        requestBody.country_of_residence,
        requestBody.question1,
        requestBody.question2,
        requestBody.tshirt_size,
        requestBody.dietary_restrictions,
        requestBody.agree_conduct,
        requestBody.share_info,
        requestBody.receive_emails,
        resume_url,
        requestBody.share_resume,
      ]
    );
    res.status(201).json({
      message: 'Application submitted',
      // TODO: We really should not be returning the application object, we could return needed information though
      application: newApplication.rows[0],
    });
    return;
  } catch (_) {
    res
      .status(500)
      .json({ message: 'Internal server error', type: ServerError.Generic });
    return;
  }
});
// /dashboard - get request to get a user's dashboard
app.get('/dashboard', async (req, res) => {
  console.log('Get request to /dashboard');
  try {
    const possibleUser = await getUser(req.headers.authorization);
    if (possibleUser.error) {
      res.status(possibleUser.code).json(possibleUser);
      return;
    }
    const user = possibleUser.user;
    // Get user
    const userTable = await pool.query(
      'SELECT name, application_status FROM users WHERE id = $1',
      [user.id]
    );

    if (userTable.rows.length === 0) {
      res.status(404).json({ message: 'User not found' });
      return;
    }
    const dashboardUser = userTable.rows[0];
    // TODO: We should not be returning the user object, we should return only the needed information
    res.json({ user: dashboardUser });
    return;
  } catch (_) {
    res
      .status(500)
      .json({ message: 'Internal server error', type: ServerError.Generic });
    return;
  }
});
// /submit-application - post request to submit an application
const submitApplicationSchema = zod.object({
  // TODO: Ensure types and improves restrictions
  // TODO: What is the difference between this and apply???
  first_name: zod.string(),
  last_name: zod.string(),
  email: zod.string().email(),
  age: zod.number(),
  gender: zod.string(),
  pronouns: zod.string(),
  race: zod.string(),
  school: zod.string(),
  major: zod.string(),
  level_of_study: zod.string(),
  country_of_residence: zod.string(),
  phonenumber: zod.string(),
  question1: zod.string(),
  question2: zod.string(),
  tshirt_size: zod.string(),
  dietary_restrictions: zod.array(zod.string()),
  agree_conduct: zod.boolean(),
  share_info: zod.boolean(),
  resume_url: zod.string(),
  receive_emails: zod.boolean(),
  share_resume: zod.boolean(),
});
app.post('/submit-application', async (req, res) => {
  console.log('Post request to /submit-application');
  try {
    // Let's start a transaction for safety
    await pool.query('BEGIN');
    const possibleUser = await getUser(req.headers.authorization);
    if (possibleUser.error) {
      res.status(possibleUser.code).json(possibleUser);
      return;
    }
    const user = possibleUser.user;
    // Prevent re-submission if the application status is already 'In Review' or 'Accepted'
    if (
      user.application_status === 'In Review' ||
      user.application_status === 'Accepted'
    ) {
      res.status(400).json({
        message: 'Application already submitted',
        type: ServerError.ApplicationAlreadySubmitted,
      });
      return;
    }
    // Write the application
    const parsedBody = await submitApplicationSchema.safeParseAsync(req.body);
    if (!parsedBody.success) {
      res
        .status(400)
        .json({ message: 'Invalid request body', type: ServerError.Generic });
      return;
    }
    const requestBody = parsedBody.data;
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
        user.id,
        requestBody.first_name,
        requestBody.last_name,
        requestBody.email,
        requestBody.age,
        requestBody.gender,
        requestBody.pronouns,
        requestBody.race,
        requestBody.school,
        requestBody.major,
        requestBody.level_of_study,
        requestBody.country_of_residence,
        requestBody.phonenumber,
        requestBody.question1,
        requestBody.question2,
        requestBody.tshirt_size,
        requestBody.dietary_restrictions.join(', '),
        requestBody.agree_conduct,
        requestBody.share_info,
        requestBody.resume_url,
        requestBody.receive_emails,
        requestBody.share_resume,
      ]
    );

    // Update the user's application status to 'In Review'
    await pool.query('UPDATE users SET application_status = $1 WHERE id = $2', [
      'In Review',
      user.id,
    ]);
    // Commit the transaction
    await pool.query('COMMIT');

    // Send final response with success message and new application details
    res.status(201).json({
      message: 'Application submitted successfully',
      // TODO: We really should not be returning the application object, we could return needed information though
      application: newApplication.rows[0],
    });
  } catch (_) {
    // Rollback the transaction
    await pool.query('ROLLBACK');
    res
      .status(500)
      .json({ message: 'Internal server error', type: ServerError.Generic });
    return;
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
