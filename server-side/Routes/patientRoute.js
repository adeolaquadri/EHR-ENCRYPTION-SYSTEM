import { Router } from "express";
import {  decryptUploadPDF, getPatientNotifications, login, patientProfile, requestMedicalHistory, resetPassword } from "../Controllers/patientController.js";
import { verifyToken, medicalHistoryLimiter } from "../Middlewares/patientAuth.js";
const route = Router();

//Patient Route
route.post('/login', login); //POST: Login

route.get('/profile', verifyToken, patientProfile); //GET: Profile

route.post('/reset-password', verifyToken, resetPassword); //POST: Reset Password

route.get('/request-history', verifyToken, requestMedicalHistory); //GET: Request Medical History

route.post('/decrypt-upload', verifyToken, decryptUploadPDF); //POST: Decrypt Encrypted Medical History

route.get('/notifications', verifyToken, getPatientNotifications); //GET: Get Notifications


export default route;