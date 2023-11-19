require('dotenv').config();

let express = require("express");
let cookieParser = require("cookie-parser");
const { createConnection } = require("mysql2");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const cors = require("cors");

const route = express.Router();

// Using environment variables for the database connection
const db = createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});


const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;


function authenticateToken(req, res, next) {
  const token = req.cookies.jwt;
  // const token = req.session.jwt;
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}


route.get("/test", (req, res) => {
  const q = "Select * FROM users";
  console.log("log: show table");
  db.query(q, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

route.post("/authenticate", (req, res) => {
  const token = req.cookies.jwt || req.cookies["jwt"];
  // const token = req.session.jwt
  // console.log(token);
  if (!token) return res.status(401).json({status: false, message: "You are not Authenticate user, Please login again", token});
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err)  return res.status(403).json({status: false, message: "You are not Authenticate user, Please login again", token});
    req.user = user;
    return res.status(200).json({status: true, message: "You are Authenticate user", token});
  });
});



route.post("/signup", (req, res) => {
  bcrypt.hash(req.body.password, 10, function (err, hash) {
    const q = "INSERT INTO users (`username`, `password`, `email`) VALUES (?)";
    const values = [req.body.username, hash, req.body.email];
    db.query(q, [values], (err, data) => {
      if (err) return res.json(err);
      res.send(data);
    });
  });
});

route.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const queryPromise = new Promise((resolve, reject) => {
        db.query("SELECT * FROM users WHERE username = ?;", [username], (err, results) => {
            if (err) {
                reject(err);
            } else {
                if (results[0]) {
                    resolve(results);
                } else {
                    res.send(false);
                }
            }
        });
    });
    const loginPromise = queryPromise
        .then((results) => {
            const result = results[0]; // Assuming you want the first row
            
            return new Promise((resolve, reject) => {
                bcrypt.compare(password, result.password, (err, isMatch) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({ isMatch, userId: result.userId, username: result.username });
                    }
                });
            });
        })
        .catch((err) => {
            console.error(err);
            res.status(500).send("Error occurred");
    });
  loginPromise
    .then(({ isMatch, userId, username }) => {
      if (isMatch) {
        const user = { id: userId, name: username };
        const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET);
        // res.cookie("jwt", accessToken, { sameSite: 'lax' });
        res.cookie("jwt", accessToken, { httpOnly: true, sameSite: 'strict', secure: true });
        // req.session.jwt = accessToken;
        res.send(true);
      } else {
        res.send(false);
      }
    })
    .catch((err) => {
      console.error(err);
      res.status(500).send("Error occurred");
    });
});

route.get("/fetchCurrentUser", authenticateToken, (req, res) => {
  res.send(req.user);
});

route.get("/isLoggedIn", (req, res) => {
  console.log("Login checking");
  // if (req.session.jwt) {
  if (req.cookies["jwt"]) {
    res.send(true);
  } else {
    res.send(false);
  }
});

function authenticateToken(req, res, next) {
  // const token = req.session.jwt;
  // const token = req.cookies.jwt;
  const token = req.cookies.jwt;
  if (token == null) return false;
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

route.post("/clear", (req, res) => {
  res.clearCookie("jwt", { path: "/" });
  // res.cookie("jwt", null, { sameSite: 'lax' });  
  // req.session.jwt = null;
  res.send(true);
});


module.exports = route;
