const mongoose=require('mongoose');
const dotenv = require('dotenv');
mongoose.set("strictQuery",true);
dotenv.config();

exports.connectDB = async() => {
    try {
        await mongoose.connect(process.env.DB_URL);
        console.log("Connected to the database");
      } catch (err) {
        console.log(err+"  error");
        process.exit(1);
      }
};