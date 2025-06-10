import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import rateLimit from 'express-rate-limit';

dotenv.config();

export const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Access Denied" });
    }
  
    const token = authHeader.split(" ")[1];
  
    try {
      const verified = jwt.verify(token, process.env.SECRET_KEY);
      req.user = verified;
      next();
    } catch (e) {
      return res.status(500).json({ message: e.message });
    }
  };
  

// Rate limit config for medical history requests
export const medicalHistoryLimiter = rateLimit({
  windowMs: 60 * 60 * 24 * 1000, // 24 hours window
  max: 1, // limit each patient to 5 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this patient. Please try again after 24 hours.'
  },
  keyGenerator: (req) => {
    // Use patient_id as unique key if available, else fallback to IP
    return req.body.patient_id || req.ip;
  },
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
});
