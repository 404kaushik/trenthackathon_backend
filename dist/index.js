"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const helmet_1 = __importDefault(require("helmet"));
const cors_1 = __importDefault(require("cors"));
const zod_1 = __importDefault(require("zod"));
const pg_1 = require("pg");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const multer_1 = __importDefault(require("multer"));
const fs_1 = __importDefault(require("fs"));
require("dotenv/config");
// TODO: use firebase for auth or an alternative managing passwords locally is just a bad idea
// TODO: use an orm for increased security
// TODO: authentication as a middleware
// TODO: use zod or an alternative for cross server client type safety.
// Schemas
const nameSchema = zod_1.default.string().min(1).max(50);
const emailSchema = zod_1.default.string().email().min(1).max(50);
const passwordSchema = zod_1.default.string().min(8).max(50);
const userSchema = zod_1.default.object({
    id: zod_1.default.number(),
    email: zod_1.default.string().email(),
    name: zod_1.default.string(),
    password: zod_1.default.string(),
    // TODO: This is never appended to the database???
    role: zod_1.default.string().optional(),
    application_status: zod_1.default.string().optional(),
});
// Error enum
var ServerError;
(function (ServerError) {
    ServerError["Generic"] = "Generic";
    ServerError["UserExists"] = "UserExists";
    ServerError["InvalidCredentials"] = "InvalidCredentials";
    ServerError["UserNotFound"] = "UserNotFound";
    ServerError["ApplicationAlreadySubmitted"] = "ApplicationAlreadySubmitted";
})(ServerError || (ServerError = {}));
// Read Constants
const SALT_ROUNDS = 10;
const PORT = process.env.PORT ?? 3000;
const DB_URL = process.env.DB_URL;
if (DB_URL == undefined)
    throw new Error('DB_URL is not defined');
const JWT_SECRET = process.env.JWT_SECRET;
if (JWT_SECRET == undefined)
    throw new Error('JWT_SECRET is not defined');
// Connect to PostgreSQL
// TODO: Use an orm for increased security
const pool = new pg_1.Pool({
    connectionString: DB_URL,
    ssl: {
        rejectUnauthorized: true, // This disables certificate validation, which is fine for testing
    },
});
// Setup Express
const app = (0, express_1.default)();
app.use((0, helmet_1.default)());
app.use((0, cors_1.default)({
    origin: [
        'https://trenthackathon.vercel.app/',
        'https://hacktrent.ca/',
        'http://localhost:3000',
    ], // or '*'
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allowed HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Allowed request headers
    credentials: true,
}));
app.use(express_1.default.json());
const storage = multer_1.default.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads/';
        if (!fs_1.default.existsSync(uploadDir)) {
            fs_1.default.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    },
});
const upload = (0, multer_1.default)({ storage: storage });
// TODO: It would be good if we applied this to to the object when signing for better round trips
const jwtPayload = zod_1.default.object({
    id: zod_1.default.number(),
    role: zod_1.default.string(),
});
const getUser = async (authHeader) => {
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
        const tokenPayload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
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
    }
    catch (err) {
        // TODO: Make this type safe
        // @ts-ignore
        if (err.name === 'TokenExpiredError') {
            return {
                error: true,
                code: 401,
                message: 'Token expired',
                type: ServerError.InvalidCredentials,
            };
        }
        else {
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
const registerSchema = zod_1.default.object({
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
        const hashedPassword = await bcryptjs_1.default.hash(password, SALT_ROUNDS);
        // Insert user into DB
        await pool.query('INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id', [name, email, hashedPassword]);
        // Commit and return
        await pool.query('COMMIT');
        res.status(201).json({ message: 'User registered' });
    }
    catch (_) {
        // Note: We drop the error as to not leak any information about the process
        await pool.query('ROLLBACK');
        res
            .status(500)
            .json({ message: 'Internal server error', type: ServerError.Generic });
        return;
    }
});
// /login - post request to login a user
const loginSchema = zod_1.default.object({
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
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
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
        const validPassword = await bcryptjs_1.default.compare(password, user.password);
        if (!validPassword) {
            res.status(400).json({
                message: 'Invalid credentials',
                type: ServerError.InvalidCredentials,
            });
            return;
        }
        // Generate JWST
        const token = jsonwebtoken_1.default.sign({ id: user.id, role: user.role }, JWT_SECRET, {
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
    }
    catch (_) {
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
    }
    catch (_) {
        res
            .status(500)
            .json({ message: 'Internal server error', type: ServerError.Generic });
        return;
    }
});
// /apply - post request to submit an application
const applySchema = zod_1.default.object({
    // TODO: Ensure types and improves restrictions
    first_name: zod_1.default.string(),
    last_name: zod_1.default.string(),
    email: emailSchema,
    age: zod_1.default.number(),
    gender: zod_1.default.string(),
    pronouns: zod_1.default.string(),
    race: zod_1.default.string(),
    school: zod_1.default.string(),
    major: zod_1.default.string(),
    level_of_study: zod_1.default.string(),
    country_of_residence: zod_1.default.string(),
    question1: zod_1.default.string(),
    question2: zod_1.default.string(),
    tshirt_size: zod_1.default.string(),
    dietary_restrictions: zod_1.default.string(),
    agree_conduct: zod_1.default.boolean(),
    share_info: zod_1.default.boolean(),
    receive_emails: zod_1.default.boolean(),
    share_resume: zod_1.default.boolean(),
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
        const resume_url = req.file != undefined
            ? `http://localhost:5001/uploads/${req.file.filename}`
            : null;
        // TODO: Is there a way todo this in a non positional manner?
        const newApplication = await pool.query(`INSERT INTO applications (
        user_id, first_name, last_name, email, age, gender, pronouns, race, school, major, 
        level_of_study, country_of_residence, question1, question2, tshirt_size, dietary_restrictions, 
        agree_conduct, share_info, receive_emails, resume_url, share_resume
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
      ) RETURNING *`, [
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
        ]);
        res.status(201).json({
            message: 'Application submitted',
            // TODO: We really should not be returning the application object, we could return needed information though
            application: newApplication.rows[0],
        });
        return;
    }
    catch (_) {
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
        const userTable = await pool.query('SELECT name, application_status FROM users WHERE id = $1', [user.id]);
        if (userTable.rows.length === 0) {
            res.status(404).json({ message: 'User not found' });
            return;
        }
        const dashboardUser = userTable.rows[0];
        // TODO: We should not be returning the user object, we should return only the needed information
        res.json({ user: dashboardUser });
        return;
    }
    catch (_) {
        res
            .status(500)
            .json({ message: 'Internal server error', type: ServerError.Generic });
        return;
    }
});
// /submit-application - post request to submit an application
const submitApplicationSchema = zod_1.default.object({
    // TODO: Ensure types and improves restrictions
    // TODO: What is the difference between this and apply???
    first_name: zod_1.default.string(),
    last_name: zod_1.default.string(),
    email: zod_1.default.string().email(),
    age: zod_1.default.number(),
    gender: zod_1.default.string(),
    pronouns: zod_1.default.string(),
    race: zod_1.default.string(),
    school: zod_1.default.string(),
    major: zod_1.default.string(),
    level_of_study: zod_1.default.string(),
    country_of_residence: zod_1.default.string(),
    phonenumber: zod_1.default.string(),
    question1: zod_1.default.string(),
    question2: zod_1.default.string(),
    tshirt_size: zod_1.default.string(),
    dietary_restrictions: zod_1.default.array(zod_1.default.string()),
    agree_conduct: zod_1.default.boolean(),
    share_info: zod_1.default.boolean(),
    resume_url: zod_1.default.string(),
    receive_emails: zod_1.default.boolean(),
    share_resume: zod_1.default.boolean(),
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
        if (user.application_status === 'In Review' ||
            user.application_status === 'Accepted') {
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
        const newApplication = await pool.query(`INSERT INTO applications (
        user_id, first_name, last_name, email, age, gender, pronouns, race, school, major, 
        level_of_study, country_of_residence, phonenumber, question1, question2, tshirt_size, 
        dietary_restrictions, agree_conduct, share_info, resume_url, receive_emails, share_resume
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
      ) RETURNING *`, [
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
        ]);
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
    }
    catch (_) {
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
