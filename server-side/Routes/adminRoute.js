import { Router } from "express";
import {
    addMedicalHistory,
    addPatient,
    getNotifications,
    getPatients,
    getRequestHistory,
    login,
    resetPassword,
    signup,
    updatePatient} from "../Controllers/adminController.js"
import { verifyToken } from "../Middlewares/adminAuth.js";
const route = Router();

//Admin Route

route.post('/login', login); //POST: Login into your account

route.post('/signup', signup); //POST: Signup

route.post('/reset-password', verifyToken, resetPassword); //POST: Reset Password

route.post('/add_patient', verifyToken, addPatient); //POST: Add New Patient

route.get('/patients', verifyToken, getPatients); //GET: Fetch all patients

route.post('/add_patient_medical_history', verifyToken, addMedicalHistory); //POST: Add Patient Medical History

route.get('/notifications', verifyToken, getNotifications); //GET: Get Notifications

route.get('/request-history', verifyToken, getRequestHistory); //GET: Get requests history

route.put('/patients/:id', verifyToken, updatePatient); //PUT: Update Patient details

export default route;