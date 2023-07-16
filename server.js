const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const app = express();
const jwt = require("jsonwebtoken");
require("dotenv").config();
const cors = require("cors");

// middlewares
app.use(cors());
app.use(express.json());
const authenticateJwt = (req, res, next) => {
	const authHeader = req.headers.authorization;
	if (authHeader) {
		const token = authHeader.split(" ")[1];
		jwt.verify(token, secretKey, (err, user) => {
			if (err) return res.sendStatus(403);

			req.user = user;
			next();
		});
	} else {
		return res.sendStatus(401);
	}
};

// env variables
const port = process.env.PORT;
const mongodbUrl = process.env.MONGODB_CONNECTION_STRING;
const secretKey = process.env.SECRET_KEY;

// create schemas
const userSchema = new mongoose.Schema({
	username: { type: String, required: true, unique: true },
	password: { type: String, required: true, unique: true },
	email: { type: String, required: true, unique: true },
	problemsSolved: [{ type: mongoose.Schema.Types.ObjectId, ref: "Problem" }],
});

const adminSchema = new mongoose.Schema({
	username: { type: String, required: true, unique: true },
	email: { type: String, required: true, unique: true },
	password: { type: String, required: true, unique: true },
	problemsCreated: [{ type: mongoose.Schema.Types.ObjectId, ref: "Problem" }],
});

const problemSchema = new mongoose.Schema({
	title: { type: String },
	description: { type: String },
	difficulty: { type: String },
	example: [
		{
			input: { type: mongoose.Schema.Types.Mixed },
			output: { type: mongoose.Schema.Types.Mixed },
		},
	],
});

// create models
const User = mongoose.model("User", userSchema);
const Admin = mongoose.model("Admin", adminSchema);
const Problem = mongoose.model("Problem", problemSchema);

// connect to db
mongoose.connect(mongodbUrl, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
});

app.post("/api/user/signup", async (req, res) => {
	const { username, email, password } = req.body;

	const user = await User.findOne({ email });
	if (user) res.status(403).json({ message: "User exist" });

	const hashedPassword = await bcrypt.hash(password, 10);
	const newUser = new User({ username, email, password: hashedPassword });
	await newUser.save();
	const token = jwt.sign({ username, role: "user" }, secretKey, {
		expiresIn: "1h",
	});
	res.status(200).json({ message: "User created", token });
});

app.post("/api/user/login", async (req, res) => {
	const { email, password } = req.body;
	const user = await User.findOne({ email });
	if (!user) res.status(403).json({ message: "User doesn't exist" });

	const isMatch = await bcrypt.compare(password, user.password);
	if (!isMatch) res.status(403).json({ message: "wrong credentials" });
	const { username } = user;
	const token = jwt.sign({ username, role: "user" }, secretKey, {
		expiresIn: "1h",
	});
	res.status(200).json({ message: "User logged in", token });
});

app.get("/api/user/problems", authenticateJwt, async (req, res) => {
	const problems = await User.findOne({
		username: req.user.username,
	}).populate("problemsSolved");
	res.status(200).json({ message: "All problems", problems });
});

app.post("/api/admin/signup", async (req, res) => {
	const { username, email, password } = req.body;
	const admin = await Admin.findOne({ email });
	if (admin) res.status(403).json({ message: "Admin exist" });
	const hashedPassword = await bcrypt.hash(password, 10);
	const newAdmin = new Admin({ username, email, password: hashedPassword });
	await newAdmin.save();
	const token = jwt.sign({ username, role: "admin" }, secretKey, {
		expiresIn: "1h",
	});
	res.status(200).json({ message: "Admin created", token });
});

app.post("/api/admin/login", async (req, res) => {
	const { email, password } = req.body;
	const admin = await Admin.findOne({ email });
	if (!admin) res.status(403).json({ message: "Admin doesn't exist" });

	const isMatch = await bcrypt.compare(password, admin.password);
	if (!isMatch) res.status(403).json({ message: "wrong credentials" });
	const { username } = admin;
	const token = jwt.sign({ username, role: "user" }, secretKey, {
		expiresIn: "1h",
	});
	res.status(200).json({ message: "Admin logged in", token });
});

app.post("/api/admin/problems", authenticateJwt, async (req, res) => {
	const admin = await Admin.findOne({ username: req.user.username });
	const newProblem = new Problem(req.body);
	// added this
	await newProblem.save();
	admin.problemsCreated.push(newProblem._id);
	await admin.save();
	const problems = await Problem.find();
	console.log(problems);
	res.status(200).json({
		message: "Problem created",
		problem: admin.problemsCreated,
	});
});

app.get("/api/admin/problems", authenticateJwt, async (req, res) => {
	const admin = await Admin.findOne({
		username: req.user.username,
	}).populate("problemsCreated");
	if (!admin) res.status(403).json({ message: "User not found" });
	res.status(200).json({
		message: "Problem fetched",
		problems: admin.problemsCreated,
	});
});

app.put("/api/admin/problems/:problemId", authenticateJwt, async (req, res) => {
	const problem = await Problem.findByIdAndUpdate(
		req.params.problemId,
		req.body,
		{ new: true }
	);
	if (!problem) res.status(404).json({ message: "problem not found" });
	res.status(200).json({ message: "Problem updated", problem });
});

app.delete(
	"/api/admin/problems/:problemId",
	authenticateJwt,
	async (req, res) => {
		const problem = await Problem.findByIdAndDelete(req.params.problemId);
		if (!problem) {
			res.status(404).json({ message: "Problem not found" });
		}
		if (problem) {
			res.sendStatus(200);
		}
	}
);

app.get("/api/allproblems", async (req, res) => {
	const problems = await Problem.find();
	res.status(200).json({ problems });
});

app.post("/api/submission/:problemId", authenticateJwt, async (req, res) => {
	const userCode = req.body.code;
	const paramNames = getParamNames(userCode);
	const stringCode = JSON.stringify(userCode);
	const func = new Function(...paramNames, stringCode);
	console.log("func", func([2, 7, 11, 15], 9)());
	console.log("func2", func([2, 7, 11, 15], 9));

	const problem = await Problem.findOne({ _id: req.params.problemId });
	problem.example.forEach((p) => {
		const obtainedOp = func(...Object.values(p.input)());
		console.log(obtainedOp);
		if (obtainedOp === p.output.result) {
			console.log("worked");
		}
	});

	res.status(200);
});

app.listen(port, () => console.log(`running on ${port}`));
