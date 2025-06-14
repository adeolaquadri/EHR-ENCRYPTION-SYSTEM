// Required modules
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import crypto from 'crypto';
import util from 'util';
import mysqlConn from '../database/connection.js';
import { Resend } from 'resend';
import jwt from 'jsonwebtoken';
import {nanoid} from 'nanoid';

const patientId = 'PAT-' + nanoid(6); // e.g., "PAT-1a2b3C"

dotenv.config();

const resend = new Resend(process.env.RESEND_API_KEY);
const query = util.promisify(mysqlConn.query).bind(mysqlConn);

// AES Key Derivation for private key encryption
const deriveKeyFromPassphrase = (passphrase, salt) =>
  crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');

// Encrypt private RSA key with AES-256-CBC using passphrase-derived key
const encryptPrivateKeyWithPassphrase = (privateKey, passphrase) => {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);
  const key = deriveKeyFromPassphrase(passphrase, salt);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update(privateKey, 'utf8', 'hex') + cipher.final('hex');
  return { encryptedPrivateKey: encrypted, iv: iv.toString('hex'), salt: salt.toString('hex') };
};

// Decrypt private RSA key using passphrase-derived AES key
export const decryptPrivateKeyWithPassphrase = (encryptedPrivateKey, passphrase, ivHex, saltHex) => {
  const iv = Buffer.from(ivHex, 'hex');
  const salt = Buffer.from(saltHex, 'hex');
  const key = deriveKeyFromPassphrase(passphrase, salt);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return decipher.update(encryptedPrivateKey, 'hex', 'utf8') + decipher.final('utf8');
};

// --- Hybrid Encryption Utilities ---

// Generate random AES key + IV
function generateAESKeyIV() {
  return {
    key: crypto.randomBytes(32), // 256-bit AES key
    iv: crypto.randomBytes(16),  // 128-bit IV
  };
}

// AES encrypt plaintext medical history data (utf8 -> base64)
function aesEncrypt(text, key, iv) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

// AES decrypt medical history data (base64 -> utf8)
function aesDecrypt(encryptedBase64, key, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedBase64, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// RSA encrypt AES key with public RSA key (returns base64)
function rsaEncryptAESKey(aesKey, publicKey) {
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    aesKey
  ).toString('base64');
}

// RSA decrypt AES key with private RSA key (input base64)
function rsaDecryptAESKey(encryptedAesKeyBase64, privateKey) {
  return crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(encryptedAesKeyBase64, 'base64')
  );
}

// Encrypt medical history data (hybrid: AES + RSA)
export const encryptMedicalHistoryHybrid = (medicalHistoryText, publicKey) => {
  const { key: aesKey, iv } = generateAESKeyIV();
  const encryptedData = aesEncrypt(medicalHistoryText, aesKey, iv);
  const encryptedAesKey = rsaEncryptAESKey(aesKey, publicKey);

  return {
    encryptedAesKey,       // base64 string
    iv: iv.toString('hex'),// hex string
    encryptedData          // base64 string
  };
};

// Decrypt medical history data (hybrid)
export const decryptMedicalHistoryHybrid = (encryptedAesKey, ivHex, encryptedData, privateKey) => {
  const aesKey = rsaDecryptAESKey(encryptedAesKey, privateKey);
  const iv = Buffer.from(ivHex, 'hex');
  return aesDecrypt(encryptedData, aesKey, iv);
};


// --- CONTROLLER: Add Patient ---

export const addPatient = async (req, res) => {
  try {
    const {firstname, middlename, lastname, email,
      phone_number, dob, gender, address, next_of_kin_name, next_of_kin_number,
      blood_type, relationship_with_next_of_kin
    } = req.body;
    const admin_email = req.user.email;

    // Check if patient already exists
    const existing = await query('SELECT * FROM patient_details WHERE patient_id = ?', [patientId]);
    if (existing.length > 0) return res.status(400).json({ message: 'Patient already exists' });

    // Generate RSA key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    });

    // Generate a secure random passphrase (to encrypt the private key)
    const passphrase = crypto.randomBytes(12).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 16);

    // Encrypt private key with passphrase
    const { encryptedPrivateKey, iv, salt } = encryptPrivateKeyWithPassphrase(privateKey, passphrase);

    // Hash patient password for authentication
    const password = process.env.DEFAULT_PASSWORD;
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store patient details + keys in DB
    await query(
      `INSERT INTO patient_details (
     patient_id, firstname, middlename, lastname, email, phone_number, dob, gender, address,
        next_of_kin_name, next_of_kin_number, password, public_key, encrypted_private_key, iv, salt, blood_type, relationship_with_next_of_kin
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
       patientId, firstname, middlename, lastname, email, phone_number, dob, gender, address, next_of_kin_name, 
        next_of_kin_number, hashedPassword, publicKey, encryptedPrivateKey, iv, salt, blood_type, relationship_with_next_of_kin
      ]
    );

    // Email the passphrase to the patient
    await resend.emails.send({
      from: 'noreply@fcahptibbursaryps.com.ng',
      to: email,
      subject: 'Your Patient Portal Passphrase',
      html: `<p>Hello ${firstname},</p>
             <p>Thank you for registering. Please keep the following secure passphrase safe. You'll need it to access your encrypted medical records:</p>
             <pre><strong>${passphrase}</strong></pre>
             <p>Keep it private. Do not share it with anyone.</p>`
    });
     await query('INSERT INTO admin_notifications (admin_email, message) VALUES (?, ?)',
        [admin_email, `Patient with id "${patientId}" added successfully and passphrase sent to email`]);
    return res.status(201).json({ message: 'Patient added successfully and passphrase sent to email' });

  } catch (error) {
    console.error('Error adding patient:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

// -- CONTROLLER: Get Patients

export const getPatients = async(req, res)=>{
  try{
    const fetchAllPatients = await query('SELECT * FROM patient_details');
    const patients = fetchAllPatients;
    return res.status(200).json({patients});

  }catch(e){
    console.error(e.message);
    return res.status(500).json({message: "Error Occured."})
  }
}

// --- CONTROLLER: Add Medical History ---

export const addMedicalHistory = async (req, res) => {
  try {
    const { patient_id, records } = req.body;
    const admin_email = req.user.email

    if (!patient_id || !Array.isArray(records) || records.length === 0) {
      return res.status(400).json({ message: "Patient ID and multiple records are required." });
    }

    // Get patient's public key
    const result = await query('SELECT public_key, lastname, firstname, middlename FROM patient_details WHERE patient_id = ?', [patient_id]);
    if (result.length === 0) return res.status(404).json({ message: 'Patient not found' });

    const publicKey = result[0].public_key;
    const name = `${result[0].lastname} ${result[0].firstname} ${result[0].middlename}`

    // Encrypt and store each record individually
    for (const record of records) {
      const { title, medical_history_text } = record;

      if (!title || !medical_history_text) {
        console.warn("Skipping invalid record:", record);
        continue;
      }

      const { encryptedAesKey, iv, encryptedData } = encryptMedicalHistoryHybrid(medical_history_text, publicKey);

      await query(
        `INSERT INTO patient_medical_history (patient_id, encrypted_aes_key, iv, title, encryptedData)
         VALUES (?, ?, ?, ?, ?)`,
        [patient_id, encryptedAesKey, iv, title, encryptedData]
      );
    }
    await query('INSERT INTO admin_notifications (admin_email, message) VALUES (?, ?)',
        [admin_email, `${name.toUpperCase} medical history records encrypted and stored successfully..`]);
    return res.status(201).json({ message: 'All medical history records encrypted and stored successfully.' });

  } catch (error) {
    console.error('Error adding medical history:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


export const sendDecryptedMedicalHistoryByEmail = async (req, res) => {
  try {
    const { patient_id, passphrase } = req.body;
    if (!patient_id || !passphrase) {
      return res.status(400).json({ message: 'Patient ID and passphrase are required' });
    }

    // Fetch patient encrypted keys and email
    const [patient] = await query(
      'SELECT encrypted_private_key, iv, salt, email FROM patient_details WHERE patient_id = ?',
      [patient_id]
    );

    if (!patient) return res.status(404).json({ message: 'Patient not found' });

    let privateKey;
    try {
      privateKey = decryptPrivateKeyWithPassphrase(patient.encrypted_private_key, passphrase, patient.iv, patient.salt);
    } catch {
      return res.status(401).json({ message: 'Invalid passphrase' });
    }

    // Fetch encrypted medical records
    const encryptedRecords = await query('SELECT * FROM patient_medical_history WHERE patient_id = ?', [patient_id]);
    if (encryptedRecords.length === 0) {
      return res.status(404).json({ message: 'No medical history found' });
    }

    // Decrypt records
    const records = encryptedRecords.map(record => decryptData(record.encryptedData, privateKey));

    // Generate PDF buffer from decrypted records text (combine or however you want)
    const {decryptedPdfBuffer, filename} = await generatePDF(records);

    // Send email with PDF attachment
    const emailResponse = await resend.emails.send({
      from: 'EHR <admin@fcahptibbursaryps.com.ng>',
      to: patient.email,
      subject: 'Your Decrypted Medical History',
      text: 'Please find attached your decrypted medical history PDF.',
      attachments: [{ filename, content: decryptedPdfBuffer, type: 'application/pdf', 
      disposition: 'attachment' }]

    });

    console.log('Email sent:', emailResponse);

    res.status(200).json({ message: 'Medical history decrypted and emailed successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

async function generatePDF(records) {
  const doc = new PDFDocument();
  const buffers = [];

  return new Promise((resolve, reject) => {
    doc.on('data', (data) => buffers.push(data));
    doc.on('end', () => {
      const buffer = Buffer.concat(buffers);
      resolve({
        decryptedPdfBuffer: buffer.toString('base64'),
        filename: `medical-history-${Date.now()}.pdf`
      });
    });

    records.forEach((rec, i) => {
      if (i !== 0) doc.addPage();
      doc.fontSize(14).text(`Record #${i + 1}\n\nTitle: ${rec.title}\n\nEncrypted:\n${rec.encryptedData}`, { width: 400, align: 'left' });
    });

    doc.end();
  });
}

export const login = async(req, res)=>{
  try{
    const {email, password} = req.body;
    if(!email || !password){
      return res.status(400).json({message: "All inputs are required!"});
    }
    const getAdmin = await query('SELECT * FROM admin WHERE email = ?', [email])
    if(getAdmin.length === 0){
      return res.status(401).json({message: "Invalid Credential."});
    }
    const admin = getAdmin[0];
    const isPasswordMatched = await bcrypt.compare(password, admin.password);

    if(!isPasswordMatched){
      return res.status(401).json({message: "Invalid Credential."});
    }
    const token = jwt.sign(
      {email: admin.email },
      process.env.ADMIN_SECRET_KEY,
      {expiresIn: "1h",
      });
      return res.status(200).json({message: "Login Successful!", token, user: admin})
  }catch(e){
    console.error(e.message);
    return res.status(500).json({message: "An error occured."});
  }
}

export const signup = async(req, res)=>{
  try{
    const {email, password, confirmpassword} = req.body;
    if(!email || !password || !confirmpassword){
      return res.status(400).json({message: "All fields are required!"});
    }
    //Check if confirm password is matched with actual password
    if(confirmpassword !== password) return res.status(400).json({message: "Passwords do not match"})

    const checkExistingAdmin = await query('SELECT * FROM admin');
    //Check if there is an existing admin
    if(!checkExistingAdmin.length === 0){
      return res.status(400).json({message: "Registration is closed! Admin already exists."});
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const addAdmin = await query('INSERT INTO admin(email, password) values(?,?)', [email, hashedPassword]);
    return res.status(201).json({message: "Account created successfully."});
  }catch(e){
    console.error(e.message);
    return res.status(500).json({message: "An error occured."});
  }
}

export const resetPassword = async(req, res)=>{
  try{
    const {oldPassword, newPassword} = req.body;
    const {email} = req.user;
    
    //Check if the admin exist...
    const getAdmin = await query("SELECT * FROM admin WHERE email = ?", [email]);
    if(getAdmin.length === 0) return res.status(404).json({message: "Invalid token!", success: false});
    const admin = getAdmin[0];

    //Check if the old password is valid...
    const isValidPassword = await bcrypt.compare(oldPassword, admin.password);
    if(!isValidPassword) return res.status(400).json({message: "Your current password is invalid", success: false});

    const password = await bcrypt.hash(newPassword, 12)
    await query("UPDATE admin SET password = ? WHERE email = ?", [password, email]);
    await query('INSERT INTO admin_notifications (admin_email, message) VALUES (?, ?)',
        [email, "Password has been reset successfully."]);
    return res.status(200).json({message: "Password has been reset successfully.", success: true});

  }catch(e){
    console.error(e.message);
    return res.status(500).json({message: "Error submitting request..."})
  }
}

export const getNotifications = async (req, res) => {
  try {
    const admin_email = req.user.email;

    const rows = await query(
      'SELECT id, message, DATE_FORMAT(created_at, "%M %d, %Y") as date, DATE_FORMAT(created_at, "%h:%i %p") as time FROM admin_notifications WHERE admin_email = ? ORDER BY created_at DESC',
      [admin_email]
    );
    return res.status(200).json({ notifications: rows });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    return res.status(500).json({ message: 'Failed to retrieve notifications.' });
  }
};