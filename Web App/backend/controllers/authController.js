import crypto from "crypto";
import jwt from "jsonwebtoken";
import { transporter } from "../utils/helpers.js";
import { otpDigitGenerate } from "../utils/otp.js";
import db from "../config/database.js"; // Assume db is exported from a config file
import dotenv from "dotenv";

dotenv.config({ path: "./backend/.env" });
console.log(otpDigitGenerate())
const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

const TOKEN_EXPIRATION = "60m"; // 15 minutes expiration


let tokenStore = [];
console.log(JWT_SECRET);

export const signup = async (req, res) => {
  const { userName, email, password } = req.body;

  if (!email || !password || !userName) {
    return res.status(400).json({ error: "All fields are required." });
  }

  const userExistQuery = `SELECT email FROM users WHERE email = ?`;
  db.query(userExistQuery, [email], async (err, results) => {
    if (err) {
      console.error("Error checking user existence :", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    console.log("User Exists : ", results);

    if (results.length > 0) {
      return res.status(400).json({
        error: "User already exists. Please log in.",
        // redirect: "login.html",
      });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    // const hashedPassword = await bcrypt.hash(password, 10); // Hash the password

    const insertQuery = `INSERT INTO users (userName, email, password, otp) VALUES (?, ?, ?, ?)`;
    db.query(
      insertQuery,
      [userName, email, password, otp],
      async (err, result) => {
        if (err) {
          console.error("Error storing user data: ", err);
          return res
            .status(500)
            .json({ error: "Failed to store data in the database." });
        } else {
          console.log("Successfuly to stored data in the database.");
        }

        // Send OTP via email
        const mailOptions = {
          from: "try.sameerdayer@gmail.com", // Change to your email
          to: email,
          subject: "Your OTP Code",
          text: `Your OTP code is ${otp}. It is valid for 10 minutes.`,
        };

        try {
          await transporter.sendMail(mailOptions);
          res.status(200).json({
            message:
              "OTP sent successfully! Redirecting to OTP Verification page...",
            redirect: `/otp-verification?email=${encodeURIComponent(email)}`,
          });
        } catch (error) {
          console.error("Error sending email:", error); // Log the error details
          return res.status(500).json({
            error: "Error sending email. Please try again later.",
            // details: error.toString(),
          });
        }
      }
    );
  });
};

export const verifyOtp = (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: "Email and OTP are required." });
  }

  const query = `SELECT otp FROM users WHERE email = ?`;
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error("Error fetching OTP from database:", err);
      return res.status(500).json({ error: "Database error." });
    }

    if (results.length === 0) {
      return res
        .status(400)
        .json({ error: "OTP not found. Please request a new one." });
    }

    const storedOtp = results[0].otp;

    if (storedOtp !== otp) {
      console.log("Inavlid Otp");
      return res.status(400).json({ error: "Invalid OTP." });
    } else {
      const updateDeleteQuery = `UPDATE users SET otp = NULL, isverified = TRUE WHERE email = ?`;
      db.query(updateDeleteQuery, [email], (deleteErr) => {
        if (deleteErr) {
          console.error("Error clearing OTP:", deleteErr);
        }
      });

      return res.json({
        message: "OTP verified successfully! Redirecting to Home page...",
        redirect: `/dashboard`,
      });
    }
  });
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "All fields are required." });
  }

  const userExistQuery = `SELECT email, password FROM users WHERE email = ?`;
  db.query(userExistQuery, [email], (err, results) => {
    if (err) {
      console.error("Error checking user existence :", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    console.log("User Exists for Login : ", results);

    if (results.length === 0) {
      return res.status(400).json({
        error: "User does not exists. Please Sign Up.",
        redirect: "/signup",
      });
    }

    if (results[0].email !== email || results[0].password !== password) {
      console.log("Incorrect email or password.");
      return res.status(400).json({
        error: "Incorrect email or password.",
      });
    }

    const isUserVerifiedQuery = `SELECT email, isVerified FROM users WHERE email = ?`;
    db.query(isUserVerifiedQuery, [email], (err, rel) => {
      console.log("Check email is verified : ", rel);

      if (err) {
        console.error("Error checking email verification status :", err);
        return res.status(500).json({ error: "Internal server error." });
      }

      if (rel.length === 0) {
        // console.log("No user found with that email.");
        return res.status(401).json({ error: "Invalid email or password." });
      }

      const user = rel[0];

      if (user.isVerified) {
        return res.json({
          message: "Successfully Login. Redirecting to Home Page...",
          redirect: "/dashboard",
        });
      } else {
        console.log(
          "User not verified. Sending OTP and redirecting to OTP Verification Page..."
        );

        const otp = crypto.randomInt(100000, 999999).toString();

        // Store OTP in database for the user (optional: use cache for better performance)
        const updateOtpQuery = `UPDATE users SET otp = ? WHERE email = ?`;
        db.query(updateOtpQuery, [otp, email], async (err) => {
          if (err) {
            console.error("Error updating OTP:", err);
            return res.status(500).json({
              error: "Internal server error.",
            });
          }

          const mailOptions = {
            from: "try.sameerdayer@gmail.com",
            to: email,
            subject: "Your OTP Code",
            text: `Your OTP code is ${otp}. It is valid for 10 minutes.`,
          };

          try {
            await transporter.sendMail(mailOptions);
            return res.json({
              message:
                "You are not verified. OTP sent. Redirecting to OTP Verification Page...",
              redirect: `/otp-verification?email=${encodeURIComponent(email)}`,
            });
          } catch (error) {
            console.error("Error sending OTP email:", error);
            return res.status(500).json({
              error: "Failed to send OTP. Please try again later.",
            });
          }
        });
      }
    });
    // });
  });
};

export const forgetPassword = (req, res) => {
  const { email } = req.body;
  if (!email) {
    return req.status(400).json({ error: "Email field required" });
  }

  const userExistQuery = `SELECT email FROM users WHERE email = ?`;
  db.query(userExistQuery, [email], async (err, results) => {
    if (err) {
      console.error("Error checking user existence :", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    console.log("User Exists for Forget Password : ", results);

    if (results.length === 0) {
      return res.status(400).json({
        error: "User does not exists. Please Sign Up.",
        redirect: "/signup",
      });
    }

    tokenStore = tokenStore.filter((el) => el.email !== email);

    const resetToken = jwt.sign({ email }, JWT_SECRET, {
      expiresIn: TOKEN_EXPIRATION,
    });

    console.log("token :", resetToken);

    // Send the reset link via email (you’ll need to set up SMTP)
    const resetLink = `http://${process.env.RESET_LINK_TEMP_IP_ADDRESS}/confirm-newpassword?token=${resetToken}`;
    
    // Log the start and end time of the token
    const startTime = new Date().toLocaleString();
    const tokenExpiry = Date.now() + 3600000; // 1 hour from
    const endTime = new Date(tokenExpiry).toLocaleString();
    console.log(`Token Start Time: ${startTime}, End Time: ${endTime}`);

    tokenStore.push({
      resetToken,
      email,
      tokenExpiry,
    });

    const mailOptions = {
      from: "try.sameerdayer@gmail.com", // Change to your email
      to: email,
      subject: "Reset Password Link",
      text: `Your link is ${resetLink}. It is valid for 1 hour.`,
    };

    try {
      await transporter.sendMail(mailOptions);
      res.status(200).json({
        message: "Reset Mail sent successfully!",
      });
    } catch (error) {
      console.error("Error sending email:", error); // Log the error details
      return res.status(500).json({
        error: "Error sending email. Please try again later.",
        // details: error.toString(),
      });
    }
    // });
  });
};

export const confirmNewPassword = async (req, res) => {
  const { token, newPassword } = req.body;

  const tokenExists = tokenStore.find((t) => t.resetToken === token);

  if (!tokenExists) {
    return res.status(400).json({ error: "Invalid or expired token." });
  }

  // Check existing password from database
  // const checkExistingPassword = `SELECT * FROM WHERE `

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log("Updating password for:", decoded);

    //   const hashedPassword = await bcrypt.hash(newPassword, 10);  // Hash new password
    const updateQuery = `UPDATE users SET password = ? WHERE email = ?`;

    db.query(updateQuery, [newPassword, decoded.email], (err) => {
      if (err) return res.status(500).json({ error: "Database error." });

      // Remove the used token from the store
      tokenStore = tokenStore.filter((t) => t.resetToken !== token);
      console.log("Token invalidated:", tokenStore);

      res.json({
        message: "Password reset successful!",
        redirect: "/",
      });
    });
  } catch (error) {
    res.status(400).json({ error: "Invalid or expired token." });
  }
};
