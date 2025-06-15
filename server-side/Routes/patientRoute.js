import { Router } from "express";

import {  decryptUploadPDF, getPatientNotifications,
    login, markNotificationAsRead, patientProfile,
   requestMedicalHistory, resetPassword } from "../Controllers/patientController.js";

   import { verifyToken, 
   medicalHistoryLimiter, 
   medicalHistoryDecryptLimiter } from "../Middlewares/patientAuth.js";
const route = Router();

//Patient Route
route.post('/login', login); //POST: Login

route.get('/profile', verifyToken, patientProfile); //GET: Profile

route.post('/reset-password', verifyToken, resetPassword); //POST: Reset Password

route.get('/request-history', verifyToken, medicalHistoryLimiter, requestMedicalHistory); //GET: Request Medical History

route.post('/decrypt-upload', verifyToken, medicalHistoryDecryptLimiter, decryptUploadPDF); //POST: Decrypt Encrypted Medical History

route.get('/notifications', verifyToken, getPatientNotifications); //GET: Get Notifications

route.patch('/notifications/:id/read', verifyToken, markNotificationAsRead); //PATCH: Auto Mark Notification as Read

export default route;