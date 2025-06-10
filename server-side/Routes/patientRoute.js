import { Router } from "express";
import {  decryptUploadPDF, login, requestMedicalHistory, resetPassword } from "../Controllers/patientController.js";
import { verifyToken, medicalHistoryLimiter } from "../Middlewares/patientAuth.js";
const route = Router();


route.get('/decrypt-upload', (req, res)=>{
   res.render('uploadPDF.ejs')
})

route.post('/login', login); //Route: Patient Login

route.post('/reset-password', verifyToken, resetPassword); //Route: Patient reset password

route.post('/request-history',medicalHistoryLimiter, requestMedicalHistory);

route.post('/decrypt-upload', decryptUploadPDF);

export default route;