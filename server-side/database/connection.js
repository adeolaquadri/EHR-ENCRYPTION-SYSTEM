import mysql from 'mysql';
import dotenv from 'dotenv';
dotenv.config();

const db = process.env.db;
const db_user = process.env.db_user;
const db_passwrord = process.env.db_password;
const db_host = process.env.db_host;
const db_port = process.env.db_port;

const mysqlConn = mysql.createConnection({
  user: db_user,
  password: db_passwrord,
  database: db,
  host: db_host,
  port: db_port
});

mysqlConn.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
  } else {
    console.log('Database connected successfully!');
  }
});

export default mysqlConn;