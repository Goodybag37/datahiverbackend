import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
// import fileUpload from "express-fileupload";
import bcrypt from "bcryptjs";
import session from "express-session";
import passport from "passport";

import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { createProxyMiddleware } from "http-proxy-middleware";

import cors from "cors";
import path from "path";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";

import axios from "axios";
import { dirname } from "path";
import { fileURLToPath } from "url";

import nodemailer from "nodemailer";
import http from "http"; // Required to create the server
import * as dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
// app.use(fileUpload());
app.use(
  session({
    secret: "your-secret-key", // Add a secret string here
    resave: false, // Session is not saved back to the store if it was not modified
    saveUninitialized: true, // Session will be created if it does not exist
    cookie: { secure: false }, // Set to true if using HTTPS
  })
);
app.set("trust proxy", 1); // trust first proxy
// const pool = new pg.Pool({
//   user: "postgres",
//   host: "localhost",
//   database: "datahiver",
//   password: "good3767589",
//   port: 5433,
// });
const pool = new pg.Pool({
  host: "aws-0-eu-central-1.pooler.supabase.com", // Use the session pooler host
  port: 5432, // Supabase session pooler port (can also be 6543, check Supabase dashboard)
  user: process.env.DB_USER, // Session pooler username (check your Supabase dashboard)
  password: process.env.DB_PASSWORD, // Your Supabase database password
  database: "postgres", // Your database name
  ssl: { rejectUnauthorized: false }, // Required for cloud databases
});

const server = http.createServer(app);
app.use(cors());
// app.use(compression());

app.use(express.json()); // This is required to parse JSON requests

app.use(
  cors({
    origin: [
      "http://localhost:3000", // Your frontend domain
      "http://datahiver.org",
    ],
    methods: ["GET", "POST", "PUT", "OPTIONS"], // Specify allowed methods
    allowedHeaders: ["Content-Type", "Authorization"], // Specify allowed headers
  })
);

app.use(
  "/api", // Adjust this path based on your needs
  createProxyMiddleware({
    target: "https://datahiver-production.up.railway.app", // Replace with the actual port of your React development server
    changeOrigin: true,
  })
);

// let transporter = nodemailer.createTransport({
//   host: "smtp.gmail.com",
//   port: 465, // For SSL
//   secure: true,
//   auth: {
//     user: "admin@datahiver.org",
//     pass: "data12345$",
//   },
//   // Use IPv4
//   lookup: (hostname, options, callback) => {
//     require("dns").lookup(hostname, { family: 4 }, callback);
//   },
// });

let transporter = nodemailer.createTransport({
  host: "mail.privateemail.com", // Namecheap SMTP server
  port: 465, // Use 465 for SSL or 587 for STARTTLS
  secure: true, // True for 465, false for 587
  auth: {
    user: process.env.NODEMAILER_USER,
    pass: process.env.NODEMAILER_PASSWORD,
  },
});

const port = process.env.PORT || 5000;
const saltRounds = 10;

app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new LocalStrategy(
    { usernameField: "email", passwordField: "password" },
    async (email, password, done) => {
      try {
        const result = await pool.query(
          "SELECT * FROM users WHERE email = $1",
          [email]
        );
        const user = result.rows[0];

        if (!user) {
          return done(null, false, { message: "Incorrect email." });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
          return done(null, false, { message: "Incorrect password." });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  console.log("Serializing user:", user);
  // Ensure user.id is non-null and unique
  done(null, user.id || "0");
});
passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];

    if (!user) {
      // If user doesn't exist, return null and false
      return done(null, false);
    }

    done(null, user);
  } catch (error) {
    done(error);
  }
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  // Store the original requested URL in session
  req.session.returnTo = req.originalUrl;

  // If not authenticated, redirect to the login route
  res.redirect("/login");
}

app.post("/log", async (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    // Query to get user info from the database
    const result = await pool.query(
      "SELECT id, email, password, name FROM users WHERE email=$1",
      [email]
    );
    const foundMail = result.rows[0];
    console.log("Query result:", foundMail); // Debugging query result

    if (foundMail) {
      const hashedPassword = foundMail.password;

      // Compare the input password with the stored hashed password
      const passwordMatch = await bcrypt.compare(password, hashedPassword);
      console.log("Password match:", passwordMatch); // Debug password match

      if (passwordMatch) {
        passport.authenticate("local", (err, user, info) => {
          if (err) {
            console.error("Passport authentication error:", err);
            return next(err);
          }
          if (!user) {
            console.log("Authentication failed: No user");
            return res.status(401).json({ message: "Authentication failed" });
          }

          req.login(user, (err) => {
            if (err) {
              console.error("Error during login:", err);
              return next(err);
            }

            res.status(200).json({
              message: "Login successful! from backend",
              userId: foundMail.id,
              email: foundMail.email,
              full_name: foundMail.name,
            });
          });
        })(req, res, next);
      } else {
        console.log("Incorrect password");
        return res.status(401).json({ message: "Incorrect password" });
      }
    } else {
      console.log("No user found with the given email");
      return res
        .status(404)
        .json({ message: "No matching email. Please create an account." });
    }
  } catch (error) {
    console.error("Error during login:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post("/register", async (req, res) => {
  console.log("something come here ");
  const { user_id, firstName, lastName, email, password, location } = req.body;

  console.log(`Received email: ${req.body}`);

  // const userId = parseInt(user_id, 10);

  // if (isNaN(userId)) {
  //   return res.status(400).json({ message: "Invalid user ID." });
  // }

  try {
    // Check if the email already exists
    const result = await pool.query("SELECT email FROM users WHERE email=$1", [
      email,
    ]);
    if (result.rows.length > 0) {
      return res
        .status(400)
        .json({ message: "Email already registered. Please log in." });
    }

    // Capitalize the full name
    const capitalizedFirstName = firstName
      .split(" ")
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(" ");

    const capitalizedLastName = lastName
      .split(" ")
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(" ");

    const capitalizedFullName = capitalizedFirstName + capitalizedLastName;

    // Insert new user (no password needed since Auth0 handles authentication)
    const newUser = await pool.query(
      `INSERT INTO users (name, first_name, last_name, email, password, location, settings, auth_id) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING auth_id`,
      [
        capitalizedFullName,
        capitalizedFirstName,
        capitalizedLastName,
        email,
        password,
        location,

        JSON.stringify({
          theme: "light",
          sidenav_type: "dark",
          navbar_fixed: "yes",
          notifications: true,
        }),

        user_id,
      ]
    );

    return res.status(201).json({
      message: "Registration successful!",
      userId: newUser.rows[0].id,
    });
  } catch (error) {
    console.error("Error during registration:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get("/profile", async (req, res) => {
  const { userId } = req.query;
  console.log("profile userId:", userId); // Check if userId is received

  try {
    // Await the query to get the actual data
    const result = await pool.query(
      "SELECT name, email, location, phone FROM users WHERE auth_id = $1",
      [userId]
    );

    // Check if user exists
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]); // Send the first row (user profile)
    console.log("profile data:", result.rows[0]); // Log the actual data
  } catch (error) {
    console.error("Database query error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/projects", async (req, res) => {
  try {
    const { title, description, sponsor, coInvestigator, sections } = req.body;
    console.log("Received data:", req.body);

    // Ensure `questions` is an array (parse if it's a string)
    const parsedQuestions =
      typeof sections === "string" ? JSON.parse(sections) : sections;

    // Validate that questions is an array before proceeding
    if (!Array.isArray(parsedQuestions)) {
      return res
        .status(400)
        .json({ success: false, error: "Questions must be an array" });
    }

    // Assign a unique ID to each question
    const updatedQuestions = parsedQuestions.map((question, index) => ({
      id: index + 1, // Generates sequential IDs (or use a UUID)
      ...question,
    }));

    const result = await pool.query(
      "INSERT INTO projects (title, description, sponsor, co_investigator, sections) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [
        title,
        description,
        sponsor,
        coInvestigator,
        JSON.stringify(updatedQuestions),
      ] // Store as JSON in PostgreSQL
    );

    res.status(201).json({ success: true, project: result.rows[0] });
  } catch (error) {
    console.error("Error inserting project:", error);
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
});

app.get("/projects", async (req, res) => {
  console.log("we get projects");
  try {
    const query =
      "SELECT project_id, title, num_workers FROM projects ORDER BY project_id DESC;";
    const { rows } = await pool.query(query);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// app.get("/project/:projectId", async (req, res) => {
//   const { projectId } = req.params;
//   const id = "531c145c-aab3-4781-97de-149c2f8feb25";
//   console.log("something reach here", projectId);
//   try {
//     const project = await pool.query(
//       "SELECT * FROM projects WHERE project_id = $1",
//       [id]
//     );
//     if (project.rows.length === 0) {
//       return res.status(404).json({ message: "Project not found" });
//     }
//     res.json(project.rows[0]);
//     console.log("something reach here33", project.rows[0]);
//   } catch (error) {
//     res.status(500).json({ message: "Error fetching project" });
//   }
// });

app.get("/project/:projectId", async (req, res) => {
  let { projectId } = req.params;
  projectId = projectId.replace(/^:/, "");

  console.log("Fetching project with ID:", projectId);

  console.log("Fetching project with ID:", projectId);

  const id = "fd5f9ac9-9f49-48f0-8c25-5d47714aeb72";

  try {
    const project = await pool.query(
      `SELECT 
        project_id, 
        title, 
        description, 
        sponsor, 
        co_investigator, 
        sections
      FROM projects 
      WHERE project_id = $1`,
      [projectId]
    );

    if (project.rows.length === 0) {
      return res.status(404).json({ message: "Project not found" });
    }

    const projectData = project.rows[0];

    // // Convert sections from JSONB to structured format (if necessary)
    // if (projectData.sections) {
    //   projectData.sections = JSON.parse(projectData.sections);
    // }

    res.json(projectData);
    console.log("Project fetched:", projectData);
  } catch (error) {
    console.error("Error fetching project:", error);
    res.status(500).json({ message: "Error fetching project" });
  }
});

app.post("/submit-survey", async (req, res) => {
  try {
    const { project_id, user_id, answers } = req.body;
    console.log("Received survey data:", req.body);

    if (!project_id || !user_id || !answers || !Array.isArray(answers)) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Insert into responses table
    const responseResult = await pool.query(
      `INSERT INTO responses (project_id, user_id, answers) 
       VALUES ($1, $2, $3) RETURNING response_id`,
      [project_id, user_id, JSON.stringify(answers)]
    );

    const response_id = responseResult.rows[0].response_id;

    // Insert each answer into the answers table
    const answerQueries = answers.map((answer) => {
      return pool.query(
        `INSERT INTO answers (response_id, project_id, section_id, question_id, answer_value) 
         VALUES ($1, $2, $3, $4, $5)`,
        [
          response_id,
          project_id,
          answer.section_id, // Using section_id from frontend
          answer.id,
          JSON.stringify(answer.answer_value),
        ]
      );
    });

    await Promise.allSettled(answerQueries);

    res.status(201).json({
      message: "Survey submitted successfully",
      response_id,
    });
  } catch (error) {
    console.error("Error submitting survey:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/become-worker", async (req, res) => {
  const { label, userId, selectedProject, selectedProjectId } = req.body;

  console.log("something reached become-worker:", req.body);

  try {
    // Get user name from the database
    const response = await pool.query(
      "SELECT name, email, id FROM users WHERE auth_id = $1",
      [userId]
    );

    // Ensure user exists
    if (response.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const name = response.rows[0].name; // Extract name from response
    const id = response.rows[0].id;
    // userEmail = response.rows[0].email;
    // Insert into workers table
    await pool.query(
      "INSERT INTO workers (full_name, project_title, user_id, project_id, role) VALUES ($1, $2, $3, $4, $5)",
      [name, selectedProject, id, selectedProjectId, label]
    );

    // Send an email
    const email = "goodnessezeanyika123@gmail.com";
    const subject = "New Worker";
    const text = `New Worker`;
    const html = `
      <h1 style="color: #15b58e; margin-left: 20%;">New Worker</h1>
      <p style="font-family: 'Times New Roman';">
        Dear Admin,<br />
        A user named <strong>${name}</strong> has applied to be a worker on a project.<br />
        <strong>User ID:</strong> ${userId}<br />
        <strong>Selected Project:</strong> ${selectedProject}<br />
        <strong>Type of Worker:</strong> ${label}<br />
      </p>
    `;

    const mailOptions = {
      from: "admin@datahiver.org",
      to: email,
      subject,
      text,
      html,
    };

    transporter.verify((error, success) => {
      if (error) {
        console.log("SMTP Connection Error:", error);
      } else {
        console.log("SMTP Connected Successfully!");
      }
    });

    await transporter.sendMail(mailOptions);
    console.log("Email was sent successfully!");

    return res.status(200).json({ message: "Worker added and email sent!" });
  } catch (error) {
    console.error("Error in /become-worker:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/log", async (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    // Query to get user info from the database
    const result = await pool.query(
      "SELECT id, email, password, name, FROM users WHERE email=$1",
      [email]
    );
    const foundMail = result.rows[0];
    let status = foundMail.email_status === "verified" ? true : false;

    if (foundMail) {
      const hashedPassword = foundMail.password;

      // Compare the input password with the stored hashed password
      const passwordMatch = await bcrypt.compare(password, hashedPassword);

      if (passwordMatch) {
        // Create a custom middleware to handle Passport.js authentication
        passport.authenticate("local", (err, user, info) => {
          if (err) {
            return next(err);
          }
          if (!user) {
            return res.status(401).json({ message: "Authentication failed" });
          }

          // Log in the user and send the response
          req.login(user, (err) => {
            if (err) {
              return next(err);
            }

            // Send response with user ID
            res.status(200).json({
              message: "Login successful! from backend",
              userId: foundMail.id,
              phone: foundMail.phone,
              id_card: foundMail.id_card,
              email: foundMail.email,
            });
          });
        })(req, res, next);
      } else {
        // Incorrect password
        return res.status(401).json({ message: "Incorrect password" });
      }
    } else {
      // No matching email
      return res
        .status(404)
        .json({ message: "No matching email. Please create an account." });
    }
  } catch (error) {
    console.error("Error during login:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

app.listen(port, () => {
  console.log(`server is listening on port ${port}`);
});
