const express = require("express");
const app = express();
const DB = require("./database").connectDB;
const sgMail = require('@sendgrid/mail');
const authRouter = require("./routes/authRoutes");


DB();
app.use(express.json());
app.use("/api/auth", authRouter);


app.listen(3000,()=>{
    console.log("listening on port 3000")
});