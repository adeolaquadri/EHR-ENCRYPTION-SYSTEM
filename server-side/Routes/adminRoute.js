import { Router } from "express";
import {
    addMedicalHistory,
    addPatient,
    sendDecryptedMedicalHistoryByEmail} from "../Controllers/adminController.js"
    
const route = Router();

//Patient Route

route.post('/add_patient', addPatient)

route.post('/add_patient_medical_history', addMedicalHistory) //POST: Add Patient Medical History

route.post('/send-decrypt-medical-record', sendDecryptedMedicalHistoryByEmail)

export default route;