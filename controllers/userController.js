const User= require("../models/userModel");
const validator = require("validator");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sendMail = require("../utils/email").sendMail;
const crypto = require("crypto");
const {promisify} = require("util");

const signToken = (id) =>{
    return jwt.sign({id},process.env.JWT_SECRET,{expiresIn: process.env.JWT_EXPIRES_IN,});
};

const createSendToken = (user,statusCode,res) =>{
    const token = signToken(user._id);
    res.status(statusCode).json({status:"success",
    token,
    data:{
        user,
    },
});
};

exports.signup = async(req,res) =>{
    try{
        const emailCheck = await User.findOne({email: req.body.email});
        if(emailCheck){
            return res.status(409).json({message:"The email is already in use"});
        }

        if(!validator.isEmail(req.body.email)){
            return res.status(400).json({message:"The email is not valid"});
        }

        if(req.body.password !== req.body.passwordConfirm){
            return res.status(400).json({message:"password and password confirm don't match"});
        }

        const newUser = await User.create({
            firstName:req.body.firstName,
            lastName:req.body.lastName,
            email:req.body.email,
            username:req.body.username,
            password:req.body.password,
            passwordConfirm:req.body.passwordConfirm,
            role:req.body.role,
        });

        //return res.status(201).json({message:"User created successfully",data: {newUser,},});
        createSendToken(newUser,201,res);

    }
    catch(err){
        res.status(500).json({message: err.message});
        console.log(err);


    }
};

exports.login = async(req,res) =>{
    try{
        const {email,password}=req.body;
        const user = await User.findOne({email});
        if(!user){
            return res.status(404).json({message: "User not found"});
        }

        if(!(await user.checkPassword(password,user.password))){
            return res.status(401).json({message:"Incorrect email or password"});
        }

        createSendToken(user,200,res);

    }catch(err){
        console.log(err);
    }
};

exports.protect = async(req,res,next) => {
    try{
        //1 we should check if the token exist
        let token;
        if(req.headers.authorization && req.headers.authorization.startsWith("Bearer")){
            token=req.headers.authorization.split(" ")[1];
        }
        if(!token){
            return res.status(401).json({message:"You are not logged in"});
        }
        //2 token verification 
        let decoded;
        try{

            decoded = await promisify(jwt.verify)(token,process.env.JWT_SECRET);

        }catch(error){
            console.log(error);
            if(error.name === "JsonWebTokenError"){
                return res.status(401).json("Invalid token");
            }
            else if(error.name === "TokenExpiredError")
            {
                return res.status(401).json("Your session token has been expired, Login again");

            }
        }
        //3 Check if the user still exist 
        const currentUser = await User.findById(decoded.id);
        if(!currentUser){
            return res.status(401).json({message:"The token owner no longer exist"});

        }

        //4 check if the user changed the password after taking the token 
        if(currentUser.passwordChangedAfterTokenIssued(decoded.iat)){
            return res.status(401).json({message:"Your poassword has been changed, please login again"});  
        }

        // we add the user to all the requests
        req.user = currentUser;
        next();


    }catch(err){
        console.log(err);
        }
}

exports.forgotPassword = async (req, res) => {
    try {
      // 1- Check if the user with the provided email exist
      const user = await User.findOne({ email: req.body.email });
  
      if (!user) {
        return res
          .status(404)
          .json({ message: "The user with the provided email does not exist." });
      }
      // 2- Create the reset token to be sended via email
  
      const resetToken = user.generatePasswordResetToken();
      await user.save({ validateBeforeSave: false });
  
      // 3- send the token via the email
      // http://127.0.0.1:3000/api/auth/resetPassword/8ba2e2cf34d6ed5e9a73447334a0aa90c46ae917c8bdab63e241c27e37de1c36
      // 3.1 : Create this url
  
      const url = `${req.protocol}://${req.get(
        "host"
      )}/api/auth/resetPassword/${resetToken}`;
  
      const msg = `Forgot your password? Reset it by visiting the following link: ${url}`;
  
      try {
        await sendMail({
          email: user.email,
          subject: "Your password reset token: (Valid for 10 min)",
          message: msg,
        });
  
       return res.status(200).json({
          status: "success",
          message: "The reset link was delivered to your email successfully",
        });
      } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });
  
       return res.status(500).json({
          message:
            "An error occured while sending the email, pease try again in a moment",
        });
      }
    } catch (err) {
      console.log(err);
    }
  };
  
  exports.resetPassword = async (req, res) => {
    try {
      const hashedToken = crypto
        .createHash("sha256")
        .update(req.params.token)
        .digest("hex");
  
      const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() },
      });
  
      if (!user) {
        return res.status(400).json({
          message: "The token is invalid, or expired. Please request a new one",
        });
      }
  
      if (req.body.password.length < 8) {
        return res.status(400).json({ message: "Password length is too short" });
      }
  
      if (req.body.password !== req.body.passwordConfirm) {
        return res
          .status(400)
          .json({ message: "Password & Password Confirm are not the same" });
      }
  
      user.password = req.body.password;
      user.passwordConfirm = req.body.passwordConfirm;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      user.passwordChangedAt = Date.now();
  
      await user.save();
      return res.status(200).json({ message: "Password changed successfully" });
    } catch (err) {
      console.log(err);
    }
  };
  