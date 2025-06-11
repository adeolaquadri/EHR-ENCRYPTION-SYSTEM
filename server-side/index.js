import express, { Router } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import adminRoute from './Routes/adminRoute.js';
import patientRoute from './Routes/patientRoute.js';
import dotenv from 'dotenv';
import multer from 'multer';
import fs from 'fs'
import cors from 'cors';
const app = express();
dotenv.config();
const {CLIENT_URL} = process.env;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(cors({
   origin: CLIENT_URL,
   credentials: true
}));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use('/admin', adminRoute);
app.use('/patient', patientRoute);


app.listen(4040, ()=>{console.log("server is listening to port 4040")})