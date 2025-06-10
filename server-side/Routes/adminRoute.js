import { Router } from "express";
import {
    addMedicalHistory,
    addPatient,
    login,
    sendDecryptedMedicalHistoryByEmail,
    signup} from "../Controllers/adminController.js"
    
const route = Router();

//Patient Route

route.post('/login', login);

route.post('/signup', signup);

route.post('/add_patient', addPatient);

route.post('/add_patient_medical_history', addMedicalHistory) //POST: Add Patient Medical History

route.post('/send-decrypt-medical-record', sendDecryptedMedicalHistoryByEmail)

export default route;