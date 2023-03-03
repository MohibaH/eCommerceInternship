const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const userSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: [true, "Please enter your firstName"],
      minLength: 3,
      trim: true,
    },
    lastName: {
      type: String,
      required: [true, "Please enter your lastName"],
      minLength: 3,
      trim: true,
    },
    email: {
      type: String,
      unique: true,
      trim: true,
      lowercase: true,
      required: [true, "Please enter your email"],
    },
    username: {
      type: String,
      unique: true,
      trim: true,
      required: [true, "Please enter your username"],
    },
    password: {
      type: String,
      minLength: 8,
      trim: true,
      required: [true, "Please enter your password"],
    },
    passwordConfirm: {
      type: String,
      minLength: 8,
      trim: true,
      required: [true, "Please confrim your password"],
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    role: {
      type: String,
      default: "user",
      enum: ["admin", "user"],
    },
    orders: [
      {
        type: Schema.Types.ObjectId,
        ref: "Order",
      },
    ],
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  try {
    if (!this.isModified("password")) {
      return next();
    }
    this.password = await bcrypt.hash(this.password, 12);
    this.passwordConfirm = undefined;
  } catch (err) {
    console.log(err);
  }
});

//  check if the password and confirm password are the same
userSchema.methods.checkPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// This function will create a random reset token
userSchema.methods.generatePasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex"); // will be sent via email

  // saved in the DB in a hashed way
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // 10 min of validity
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

module.exports = mongoose.model("User", userSchema);