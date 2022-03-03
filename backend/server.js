import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import crypto from "crypto";
import bcrypt from "bcrypt";

//setting up local database
const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/authAPI";
mongoose.connect(mongoUrl, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: true,
});
mongoose.Promise = Promise;

// ******** Schemas ******** //
// Model to Sign Up & Sign in user
const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    unique: true,
    required: true,
  },
  email: {
    type: String,
    unique: true,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  task: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "task",
  },

  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString("hex"),
  },
});
const User = mongoose.model("User", UserSchema);

// ******** Defined Port ******** //
const port = process.env.PORT || 8080;
const app = express();

// ******** Middlewear ******** //
app.use(cors());
app.use(express.json());

// ******** Authentication function ******** //.
const authenticateUser = async (req, res, next) => {
  const accessToken = req.header("Authorization");

  try {
    const user = await User.findOne({ accessToken });
    if (user) {
      next();
    } else {
      res.status(401).json({
        response: {
          message: "Please, log in",
        },
        success: false,
      });
    }
  } catch (error) {
    res.status(400).json({ response: error, success: false });
  }
};

// ******** ENDPOINTS ******** //
// GET endpoints
app.get("/", (req, res) => {
  res.send("Start");
});

app.get("/home", authenticateUser);
app.get("/home", async (req, res) => {
  res.send("Home");
});

// Get all tasks by USER ID --- WORKS!
app.get("/tasks/:userId", authenticateUser);
app.get("/tasks/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const tasks = await Task.find({ user: userId })
      .populate("user")
      .sort({ createdAt: "desc" });
    res.status(201).json({ response: tasks, success: true });
  } catch (error) {
    res.status(400).json({ response: error, success: false });
  }
});

// POST endpoints

// SIGNUP endpoint --- WORKS!
app.post("/signup", async (req, res) => {
  const { username, password, email } = req.body;

  try {
    const salt = bcrypt.genSaltSync();

    if (password.length < 5) {
      throw "Password must be at least 5 characters long";
    }

    const newUser = await new User({
      username,
      password: bcrypt.hashSync(password, salt),
      email,
    }).save();

    res.status(201).json({
      response: {
        userId: newUser._id,
        username: newUser.username,
        email: newUser.email,
        accessToken: newUser.accessToken,
      },
      success: true,
    });
  } catch (error) {
    res.status(400).json({ response: error, success: false });
  }
});

// SIGNIN endpoint --- WORKS!
app.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (user && bcrypt.compareSync(password, user.password)) {
      res.status(200).json({
        response: {
          userId: user._id,
          username: user.username,
          email: user.email,
          accessToken: user.accessToken,
        },
        success: true,
      });
    } else {
      res.status(404).json({
        response: "Username or password doesn't match",
        success: false,
      });
    }
  } catch (error) {
    res.status(400).json({ response: error, success: false });
  }
});

// Start the server
app.listen(port, () => {
  // eslint-disable-next-line
  console.log(`Server running on http://localhost:${port}`);
});
