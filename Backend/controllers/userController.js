import userModel from "../models/userModel.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import validator from "validator";



const createToken = (userId) => {
    return jwt.sign({ id:userId }, process.env.JWT_SECRET);
  };


// login user
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    // check the email for user is exist
    const user = await userModel.findOne({email});
    if (!user) {
      res.json({ success: false, message: "User not found" });
    }

    // check the passwords
    const isMatch = await bcrypt.compare(password,user.password);

    if (!isMatch) {
      res.json({ success: false, message: "invalid credentials" });
    }

    const token = createToken(user._id);
    res.json({ success: true, token });
  } 

  catch (error) {
    console.log(error)
    res.json({success:false,message:'error'})
  }
};


  

// registerUser
const registerUser = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // check user exist
    const exist = await userModel.findOne({ email });
    if (exist) {
      return res.json({ success: false, message: "User already exist" });
    }

    // validate email and strong password
    if (!validator.isEmail(email)) {
      return res.json({ success: false, message: "Please enter valid email" });
    }

    if (password.length < 8) {
      return res.json({
        success: false,
        message: "please enter a strong password",
      });
    }

    // hashing user password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // create new user
    const newUser = new userModel({
      name: name,
      email: email,
      password: hashedPassword,
    });

    // save the user
    const user = await newUser.save();
    const token = createToken(user._id);
    res.json({ success: true, token });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: "error" });
  }
};

export { loginUser, registerUser };
