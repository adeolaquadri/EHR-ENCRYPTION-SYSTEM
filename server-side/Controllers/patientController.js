// patientController.js
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import util from "util";
import mysqlConn from "../database/connection.js";
import PDFDocument from 'pdfkit';
import multer from 'multer';
import { Resend } from "resend";
import { PassThrough } from "stream";
import fs from 'fs'
import dotenv from 'dotenv';
import crypto from "crypto"
import PDFParser from "pdf2json";
import { decryptPrivateKeyWithPassphrase, decryptMedicalHistoryHybrid } from "./adminController.js";

dotenv.config();
const resend = new Resend(process.env.RESEND_API_KEY);
const query = util.promisify(mysqlConn.query).bind(mysqlConn);

function hashBase64(base64String) {
  return crypto.createHash('sha256').update(base64String.trim().replace(/\s+/g, '')).digest('hex');
}


// Login Controller
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "All fields are required!" });

    const getPatient = await query('SELECT * FROM patient_details WHERE email = ?', [email]);
    const patient = getPatient[0];
    if (!patient) return res.status(401).json({ message: "Invalid credential" });

    const validPassword = await bcrypt.compare(password, patient.password);
    if (!validPassword) return res.status(401).json({ message: "Incorrect Password" });

    const token = jwt.sign({ id: patient.patient_id }, process.env.SECRET_KEY, { expiresIn: "1d" });
    const { encrypted_private_key, iv } = patient;
    return res.status(200).json({ message: "Login successfully", token, user: patient, encrypted_private_key, iv });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Internal server error" });
  }
};

// Reset Password Controller
export const resetPassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const {id} = req.user;
    if (!oldPassword || !newPassword) return res.status(400).json({ message: "All fields are required!" });

    const [patient] = await query('SELECT password FROM patient_details WHERE patient_id = ?', [id]);
    const validPassword = await bcrypt.compare(oldPassword, patient.password);
    if (!validPassword) return res.status(400).json({ message: "Your current password is invalid" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await query('UPDATE patient_details SET password = ? WHERE patient_id = ?', [hashedPassword, id]);

     await query('INSERT INTO patient_notifications (patient_id, message) VALUES (?, ?)',
      [id, "Password updated successfully."]);
    return res.status(200).json({ message: "Password updated successfully." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Internal server error!" });
  }
};


// Request Medical History Controller
export const requestMedicalHistory = async (req, res) => {
  try {
    const patient_id  = req.user.id;
    if (!patient_id) return res.status(400).json({success:false, message: "Input is required!" });

    const patient = await query('SELECT firstname, email, lastname, middlename FROM patient_details WHERE patient_id = ?', [patient_id]);
    if (patient.length === 0) return res.status(404).json({success:false, message: "Patient not found" });

    const fullName = `${patient[0].lastname} ${patient[0].firstname} ${patient[0].middlename}`;
    const email = patient[0].email;

    const records = await query('SELECT title, encryptedData FROM patient_medical_history WHERE patient_id = ?', [patient_id]);
    if(records.length === 0) return res.status(404).json({success: false, message:"No Medical History Record."})
    const { encryptedPdfBuffer, filename } = await generateEncryptedPDF(records, fullName);

    const emailResponse = await resend.emails.send({
      from: 'EHR <admin@fcahptibbursaryps.com.ng>',
      to: email,
      subject: 'Your Encrypted Medical History',
      text: 'Please log in to your secure portal and use your decryption passphrase to view this file.',
      attachments: [{ filename, content: encryptedPdfBuffer, type: 'application/pdf', disposition: 'attachment' }]
    });

    console.log("Email sent result:", emailResponse);
      await query('INSERT INTO patient_notifications (patient_id, message) VALUES (?, ?)',
      [patient_id, "Medical history has been emailed securely."]);

      await query(
      "INSERT INTO request_history (patient_id) VALUES (?)",
      [patient_id]
    );
    res.json({ success: true, message: 'Medical history has been emailed securely.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to process request.' });
  }
};

async function generateEncryptedPDF(records, patientName) {
  const doc = new PDFDocument({
    size: 'A4',
    margins: { top: 72, bottom: 72, left: 72, right: 72 }
  });
  const buffers = [];

  const hospitalDetails = {
    name: "Federal College of Animal Health & Production Technology",
    address: "Ibadan, Oyo State, Nigeria",
    phone: "+234 123 456 7890",
    email: "info@fcahptibursaryps.com.ng"
  };

  function drawHeader() {
    doc
      .font('Helvetica-Bold')
      .fontSize(18)
      .fillColor('#2c3e50')
      .text(hospitalDetails.name, { align: 'center' })
      .moveDown(0.3);

    doc
      .font('Helvetica')
      .fontSize(11)
      .fillColor('#34495e')
      .text(hospitalDetails.address, { align: 'center' });

    doc
      .fontSize(10)
      .text(`Phone: ${hospitalDetails.phone} | Email: ${hospitalDetails.email}`, { align: 'center' })
      .moveDown(1);

    doc.moveTo(doc.page.margins.left, doc.y)
      .lineTo(doc.page.width - doc.page.margins.right, doc.y)
      .strokeColor('#bdc3c7')
      .lineWidth(1)
      .stroke();

    doc.moveDown(1);
  }

  function drawPatientInfo() {
    doc
      .font('Helvetica-Bold')
      .fontSize(14)
      .fillColor('#2c3e50')
      .text(`Patient Name: `, { continued: true })
      .font('Helvetica')
      .text(patientName)
      .moveDown(1);
  }

  function drawRecord(index, rec) {
    doc
      .font('Helvetica-Bold')
      .fontSize(13)
      .fillColor('#2980b9')
      .text(`Record #${index + 1}`, { underline: true })
      .moveDown(0.3);

    doc
      .font('Helvetica-Bold')
      .fontSize(12)
      .fillColor('#34495e')
      .text(`Title: `, { continued: true })
      .font('Helvetica')
      .text(rec.title)
      .moveDown(0.5);

    doc
      .font('Helvetica')
      .fontSize(11)
      .fillColor('black')
      .text(`Encrypted Data:`, { underline: false })
      .moveDown(0.3);

    // wrap encrypted data nicely
doc
  .font('Courier')
  .fontSize(10)
  .fillColor('black')
  .text(rec.encryptedData, {
    width: doc.page.width - doc.page.margins.left - doc.page.margins.right,
    align: 'left',
    lineBreak: false,
  });

  }

  return new Promise((resolve, reject) => {
    doc.on('data', (chunk) => buffers.push(chunk));
    doc.on('end', () => {
      const buffer = Buffer.concat(buffers);
      resolve({
        encryptedPdfBuffer: buffer.toString('base64'),
        filename: `medical-history-${Date.now()}.pdf`
      });
    });

    records.forEach((rec, index) => {
      if (index !== 0) doc.addPage();

      drawHeader();
      drawPatientInfo();
      drawRecord(index, rec);
    });

    doc.end();
  });
}



const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

// Helper to extract lines of text from pdf2json output
function extractTextLinesFromPdf2Json(pdfData) {
  const pages = pdfData.Pages || [];
  const lines = [];

  for (const page of pages) {
    const texts = page.Texts;
    const linesMap = new Map();

    for (const textObj of texts) {
      const y = Math.round(textObj.y * 10) / 10;
      const txt = decodeURIComponent(textObj.R[0].T);

      if (!linesMap.has(y)) linesMap.set(y, []);
      linesMap.get(y).push({ x: textObj.x, text: txt });
    }

    const sortedY = [...linesMap.keys()].sort((a, b) => a - b);
    for (const y of sortedY) {
      const words = linesMap.get(y);
      words.sort((a, b) => a.x - b.x);
      lines.push(words.map(w => w.text).join(' '));
    }
  }
  return lines;
}

// Helper to extract encrypted records from lines
function extractEncryptedRecords(lines) {
  const records = [];
  let currentRecord = null;
  let inEncryptedDataBlock = false;

  lines.forEach((line) => {
    line = line.trim();

    // Start of new record
    if (line.startsWith("Record #")) {
      if (currentRecord) {
        records.push(currentRecord);
      }

      const recordNumber = line.match(/Record\s+#(\d+)/i)?.[1] || 'Unknown';
      currentRecord = {
        recordNumber,
        title: '',
        encryptedBase64: ''
      };
      inEncryptedDataBlock = false;
    }

    // Title line
    else if (line.startsWith("Title:") && currentRecord) {
      currentRecord.title = line.replace("Title:", "").trim();
    }

    // Start collecting encrypted data
    else if (line.startsWith("Encrypted Data:") && currentRecord) {
      inEncryptedDataBlock = true;
    }

    // Continue encrypted data
    else if (inEncryptedDataBlock && currentRecord) {
      if (line === '' || line.startsWith("Record #")) {
        inEncryptedDataBlock = false; // Stop if blank or next record starts
      } else {
        currentRecord.encryptedBase64 += line;
      }
    }
  });

  // Push the last record
  if (currentRecord) {
    records.push(currentRecord);
  }

  return records;
}



// Generate decrypted PDF from records
async function generateDecryptedPDF(records, patientName) {
  const doc = new PDFDocument({ size: 'A4', margins: { top: 72, bottom: 72, left: 72, right: 72 } });
  const buffers = [];

  const hospitalDetails = {
    name: "Federal College of Animal Health & Production Technology",
    address: "Ibadan, Oyo State, Nigeria",
    phone: "+234 123 456 7890",
    email: "info@fcahptibursaryps.com.ng"
  };

  return new Promise((resolve, reject) => {
    doc.on('data', (chunk) => buffers.push(chunk));
    doc.on('end', () => {
      const buffer = Buffer.concat(buffers);
      resolve(buffer);
    });

    records.forEach((rec, i) => {
      if (i !== 0) doc.addPage();

      // Hospital header
      doc
        .fontSize(16)
        .fillColor('#333333')
        .text(hospitalDetails.name, { align: 'center' })
        .moveDown(0.2);

      doc
        .fontSize(10)
        .fillColor('#555555')
        .text(hospitalDetails.address, { align: 'center' });

      doc
        .text(`Phone: ${hospitalDetails.phone} | Email: ${hospitalDetails.email}`, { align: 'center' })
        .moveDown(1);

      // Patient name
      doc
        .fillColor('#000000')
        .fontSize(14)
        .text(`Patient: ${patientName}`, { align: 'left' })
        .moveDown(1);

      // Record content
      doc
        .fontSize(14)
        .fillColor('black')
        .text(`Record #${rec.recordNumber}`, { underline: true })
        .moveDown(0.5);

      doc.fontSize(12).text(`Title: ${rec.title}`).moveDown(1);

      doc.fontSize(10).text(`Decrypted Data:\n${rec.decrypted}`, {
        width: 450,
        align: 'left'
      });
    });

    doc.end();
  });
}

// Send email with decrypted PDF using Resend
async function sendEmailWithAttachment(toEmail, patientName, pdfBuffer, patientId) {
  const base64Pdf = pdfBuffer.toString('base64');

 const emailRes = await resend.emails.send({
    from: 'EHR <admin@fcahptibbursaryps.com.ng>', // Your verified sender email
    to: toEmail,
    subject: 'Your Decrypted Medical History',
    text: `Dear ${patientName},\n\nPlease find attached your decrypted medical history.\n\nRegards,\nFCAHPT Team`,
    attachments: [
      {
        filename: `medical-history-${patientId}.pdf`,
        content: base64Pdf,
        contentType: 'application/pdf',
        encoding: 'base64',
      }
    ]
  });
  console.log(emailRes.data)
}

// Main decrypt upload PDF handler
export const decryptUploadPDF = [
  upload.single('pdf'),

  async (req, res) => {
    const { passphrase } = req.body;
    const patient_id = req.user.id;

    if (!req.file || !passphrase) {
      return res.status(400).json({ message: 'Missing PDF file or passphrase.' });
    }

    try {
      // 1. Get patient metadata
      const [patientRow] = await query(
        'SELECT encrypted_private_key, iv, salt, email, lastname, firstname, middlename FROM patient_details WHERE patient_id = ?',
        [patient_id]
      );
      if (!patientRow) return res.status(404).json({ message: 'Patient not found.' });

      const { encrypted_private_key, iv, salt, email, lastname, firstname, middlename } = patientRow;
      const patient_email = email;
      const patient_name = `${lastname} ${firstname} ${middlename}`;

      // 2. Fetch all encrypted medical history records
      const historyResult = await query(
        'SELECT encrypted_aes_key, iv, encryptedData FROM patient_medical_history WHERE patient_id = ?',
        [patient_id]
      );
      if (historyResult.length === 0) return res.status(404).json({ message: 'No medical history found.' });
      console.log("Database history records:", historyResult.length);

      // 3. Decrypt the private key
      let privateKeyPem;
      try {
        privateKeyPem = decryptPrivateKeyWithPassphrase(encrypted_private_key, passphrase, iv, salt);
      } catch (err) {
        console.error("Invalid passphrase:", err.message);
        return res.status(401).json({ message: 'Invalid passphrase. Decryption failed.' });
      }

      // 4. Parse uploaded PDF
      const pdfParser = new PDFParser();
      const pdfData = await new Promise((resolve, reject) => {
        pdfParser.on("pdfParser_dataError", err => reject(err.parserError));
        pdfParser.on("pdfParser_dataReady", pdfData => resolve(pdfData));
        pdfParser.loadPDF(req.file.path);
      });

      // 5. Extract and normalize PDF encrypted blocks
      const allLines = extractTextLinesFromPdf2Json(pdfData);
      const encryptedRecords = extractEncryptedRecords(allLines);
      console.log("Extracted encrypted records:", encryptedRecords.length);

      // 6. Build hash map from DB
      const dbRecordMap = new Map();
      historyResult.forEach((record) => {
        const hash = hashBase64(record.encryptedData);
        dbRecordMap.set(hash, record);
      });

      // 7. Decrypt each PDF record
      const decryptedResults = encryptedRecords.map(({ recordNumber, title, encryptedBase64 }) => {
        const cleaned = encryptedBase64.trim().replace(/\s+/g, '');
        const hash = hashBase64(cleaned);
        const matched = dbRecordMap.get(hash);

        console.log(`Matching for record #${recordNumber}...`);
        if (!matched) {
          console.log(`❌ No exact hash match for: ${hash}`);

          // Optional fallback match
          const fallback = historyResult.find((item) => {
            const dbData = item.encryptedData.trim().replace(/\s+/g, '');
            return dbData.includes(cleaned) || cleaned.includes(dbData);
          });

          if (!fallback) {
            return { recordNumber, title, decrypted: 'No matching encrypted data found.' };
          }

          try {
            const decrypted = decryptMedicalHistoryHybrid(
              fallback.encrypted_aes_key,
              fallback.iv,
              fallback.encryptedData,
              privateKeyPem
            );
            return { recordNumber, title, decrypted };
          } catch (err) {
            console.error(`Failed to decrypt fallback record #${recordNumber}:`, err.message);
            return { recordNumber, title, decrypted: 'Failed to decrypt record (fallback).' };
          }
        }

        // Exact hash match
        try {
          const decrypted = decryptMedicalHistoryHybrid(
            matched.encrypted_aes_key,
            matched.iv,
            matched.encryptedData,
            privateKeyPem
          );
          return { recordNumber, title, decrypted };
        } catch (err) {
          console.error(`Failed to decrypt record #${recordNumber}:`, err.message);
          return { recordNumber, title, decrypted: 'Failed to decrypt record.' };
        }
      });

      console.log("Final decrypted results:", decryptedResults.length);

      // 8. Generate and email PDF
      const decryptedPdfBuffer = await generateDecryptedPDF(decryptedResults, patient_name);
      await sendEmailWithAttachment(patient_email, patient_name, decryptedPdfBuffer, patient_id);

      // 9. Clean up
      fs.unlinkSync(req.file.path);
      await query('INSERT INTO patient_notifications (patient_id, message) VALUES (?, ?)',
        [patient_id, "Decryption successful. PDF sent by email."]);

      return res.status(200).json({ message: 'Decryption successful. PDF sent by email.' });

    } catch (err) {
      console.error("Decryption error:", err);
      return res.status(500).json({ message: 'Error decrypting the PDF.' });
    }
  }
];

export const patientProfile = async(req, res)=>{
  try{
    const {id} = req.user;
    const patient_id = id;
    const patient = await query("SELECT * FROM patient_details WHERE patient_id = ?", [patient_id]);
    return res.status(200).json({patient})
  }catch(e){
    console.error(e.message);
    return res.status(500).json({message: "Internal Server Error."})
  }
}

export const getPatientNotifications = async (req, res) => {
  try {
    const patient_id = req.user.id;

    const rows = await query(
      'SELECT id, message, DATE_FORMAT(created_at, "%M %d, %Y") as date, DATE_FORMAT(created_at, "%h:%i %p") as time FROM patient_notifications WHERE patient_id = ? ORDER BY created_at DESC',
      [patient_id]
    );
    return res.status(200).json({ notifications: rows });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    return res.status(500).json({ message: 'Failed to retrieve notifications.' });
  }
};


export const markNotificationAsRead = async (req, res) => {
  const { id } = req.params;
  const patient_id = req.user.id;

  try {
    const result = await query(
      `UPDATE patient_notifications SET is_read = TRUE WHERE id = ? AND patient_id = ?`,
      [id, patient_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Notification not found." });
    }

    res.status(200).json({ message: "Notification marked as read." });
  } catch (error) {
    console.error("Mark read error:", error);
    res.status(500).json({ message: "Error updating notification." });
  }
};
