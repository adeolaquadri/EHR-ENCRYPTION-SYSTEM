// Required modules
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import crypto from 'crypto';
import util from 'util';
import mysqlConn from '../database/connection.js';
import { Resend } from 'resend';

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
    const {
      patient_id, insurance_id, firstname, middlename, lastname, email,
      phone_number, dob, gender, address, next_of_kin_name, next_of_kin_number,
      blood_type, password
    } = req.body;

    // Check if patient already exists
    const existing = await query('SELECT * FROM patient_details WHERE patient_id = ?', [patient_id]);
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
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store patient details + keys in DB
    await query(
      `INSERT INTO patient_details (
        patient_id, insurance_id, firstname, middlename, lastname, email, phone_number, dob, gender, address,
        next_of_kin_name, next_of_kin_number, password, public_key, encrypted_private_key, iv, salt, blood_type
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        patient_id, insurance_id, firstname, middlename, lastname, email, phone_number, dob, gender, address,
        next_of_kin_name, next_of_kin_number, hashedPassword, publicKey, encryptedPrivateKey, iv, salt, blood_type
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

    return res.status(201).json({ message: 'Patient added successfully and passphrase sent to email' });

  } catch (error) {
    console.error('Error adding patient:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


// --- CONTROLLER: Add Medical History ---

export const addMedicalHistory = async (req, res) => {
  try {
    const { patient_id, title, medical_history_text } = req.body;

    // Get patient's public key from DB
    const result = await query('SELECT public_key FROM patient_details WHERE patient_id = ?', [patient_id]);
    if (result.length === 0) return res.status(404).json({ message: 'Patient not found' });

    const publicKey = result[0].public_key;

    // Encrypt medical history using hybrid method
    const { encryptedAesKey, iv, encryptedData } = encryptMedicalHistoryHybrid(medical_history_text, publicKey);

    // Store encrypted medical history in a separate table
    await query(
      `INSERT INTO patient_medical_history (patient_id, encrypted_aes_key, iv, title, encryptedData)
       VALUES (?, ?, ?, ?, ?)`,
      [patient_id, encryptedAesKey, iv, title, encryptedData]
    );

    return res.status(201).json({ message: 'Medical history encrypted and stored successfully' });

  } catch (error) {
    console.error('Error adding medical history:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


// --- CONTROLLER: Get Decrypted Medical History ---

// export const getDecryptedMedicalHistory = async (req, res) => {
//   try {
//     const { patient_id, passphrase } = req.body;

//     // Get encrypted private key, iv, salt from DB
//     const result = await query(
//       'SELECT encrypted_private_key, iv, salt FROM patient_details WHERE patient_id = ?',
//       [patient_id]
//     );

//     if (result.length === 0) return res.status(404).json({ message: 'Patient not found' });

//     const { encrypted_private_key, iv, salt } = result[0];

//     // Decrypt private key using passphrase
//     const privateKey = decryptPrivateKeyWithPassphrase(encrypted_private_key, passphrase, iv, salt);

//     // Get patient's encrypted medical history
//     const historyResult = await query(
//       'SELECT encrypted_aes_key, iv, encrypted_data FROM patient_medical_history WHERE patient_id = ? ORDER BY created_at DESC LIMIT 1',
//       [patient_id]
//     );

//     if (historyResult.length === 0) return res.status(404).json({ message: 'No medical history found' });

//     const { encrypted_aes_key, iv: historyIv, encrypted_data } = historyResult[0];

//     // Decrypt medical history
//     const decryptedMedicalHistory = decryptMedicalHistoryHybrid(encrypted_aes_key, historyIv, encrypted_data, privateKey);

//     return res.status(200).json({ medical_history: decryptedMedicalHistory });

//   } catch (error) {
//     console.error('Error decrypting medical history:', error);
//     return res.status(500).json({ message: 'Internal server error or invalid passphrase' });
//   }
// };



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

