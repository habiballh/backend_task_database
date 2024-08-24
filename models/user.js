const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// great the schema for the models
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    trim: true,
    minlength: 8,
    validate(value) {
      let password = new RegExp(
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])"
      );
      if (!password.test(value))
        throw new Error(
          "Password must include upper case , lower case , letters and numbers"
        );
    },
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    unique: true,
    validate(val) {
      if (!validator.isEmail(val)) {
        throw new Error("Invalid email address");
      }
    },
  },
  age: {
    type: Number,
    default: 18,
    validate(val) {
      if (val<=0) {
        throw new Error("Age must be a positive number");
      }
    },
  },
  city: {
    type: String,
  },
  tokens: [{ type: String, required: true }],
});

userSchema.pre("save", async function () {
  const user = this; // => document
  if (user.isModified("password")) {
    user.password = await bcrypt.hash(user.password, 8);
  }
});
////////////////////////////////////////////////////////////////////////////////////////////////////////
//login
userSchema.statics.findByCredentials = async (email, password) => {
  const user = await User.findOne({ email });
  if (!user) {
    throw new Error("Unable to login");
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new Error("Unable to login");
  }
  return user;
};
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
// token
userSchema.methods.generateToken = async function () {
  const user = this;
  const token = jwt.sign({ _id: user._id.toString() }, "habib200");
  user.tokens = user.tokens.concat(token);
  await user.save();
  return token;
};
//////////////////////////////////////////////////////////////////////////////
// hide privte data
userSchema.methods.toJSON = function () {
  const user = this;
  const userObject = user.toObject();
  delete userObject.password;
  delete userObject.tokens;
  return userObject;
};
//////////////////////////////////////////////////////////////////////////////
const User = mongoose.model("User", userSchema);

module.exports = User;
