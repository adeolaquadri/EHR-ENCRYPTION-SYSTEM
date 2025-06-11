import { Router } from "express";
import {
    addMedicalHistory,
    addPatient,
    getPatients,
    login,
    sendDecryptedMedicalHistoryByEmail,
    signup} from "../Controllers/adminController.js"
import { verifyToken } from "../Middlewares/adminAuth.js";
const route = Router();

//Patient Route

route.post('/login', login);

route.post('/signup', signup);

route.post('/add_patient', verifyToken, addPatient);

route.get('/patients', verifyToken, getPatients);

route.post('/add_patient_medical_history', addMedicalHistory) //POST: Add Patient Medical History

route.post('/send-decrypt-medical-record', sendDecryptedMedicalHistoryByEmail)

export default route;