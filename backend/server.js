const express = require("express");
const {open} = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");
const jsonwebtoken = require("jsonwebtoken");

const dbPath = path.join(__dirname, "data.db");

const app = express();

app.use(express.json());
app.use(cors());

let db;

const initializeDbAndServer = async () => {
    try{
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        })
        app.listen(3000, () => {
            console.log("Server Running at http://localhost:3000/");
        })
    }
    catch(e){
        console.log(e.message)
        process.exit(1)
    }
}
initializeDbAndServer()

const RegisterMiddleware = async (request, response, next) => {
    const {username, email, password} = request.body;
    try{
        const checkUser = `
            SELECT * FROM users
            WHERE username = ?
        `
        const res = await db.get(checkUser, [username]);

        if (res !== undefined){
            response.status(400);
            response.send("User already exists");
        }
        else{
            next();
        }
    }catch(e){
        response.send(e.message);
    }
}

app.post("/register", RegisterMiddleware, async (request, response) => {
    const {username, email, password} = request.body;
    
    const hashedPassword = await bcrypt.hash(password, 10);
    try{
        const registerUser = `
            INSERT INTO users(username, email, password)
            VALUES(?, ?, ?);
        `
        await db.run(registerUser, [username, email, hashedPassword]);
        response.send("Successfully Registered");
    }
    catch(e){
        response.send(e.message);
    }
})


//Login API

app.post("/login", async (request, response) => {
    const {username, password} = request.body;
    try{
        const checkUser = `
            SELECT * FROM users
            WHERE username = ?
        `
        const res = await db.get(checkUser, [username]);

        if (res === undefined){
            response.status(400);
            response.send("Not an existing User");
        }
        else{
            
            const comparePassword = await bcrypt.compare(password, res.password);
           
            if (comparePassword === false){
                response.status(400);
                response.send("Incorrect Password");
            }
            else{
                
                const payload = {
                    username
                }
                const jwtToken = jsonwebtoken.sign(payload, "nari");
               
                response.status(200);
                response.send({jwt_token: jwtToken})
            }
        }
    }catch(e){
        response.send(e.message);
    } 
})


//JWT Verification Middleware API

const JwtVerificationMiddleware = (request, response, next) => {
    const authHeader = request.headers["authorization"];

    if (!authHeader){
        response.status(400);
        response.send("Missing Token");
    }
    else {
        const token = authHeader.split(" ")[1];
        jsonwebtoken.verify(token, "nari", (err, payload) => {
            if (err){
                response.status(400);
                response.send("Invalid jwt token")
            }
            else{
                request.payload = payload;
                next();
            }
        })
    }

}

//userstransactions API

app.post("/userform", JwtVerificationMiddleware, async (request, response) => {
    const {amount, category, date} = request.body;
    const {username} = request.payload;

    try{
        const userIdQuery = `
        SELECT id from users
        WHERE username=?
        `
        const userId = await db.get(userIdQuery, [username])
        
        const userstransactionsQuery = `
            INSERT INTO users_transactions(users_id, amount, category, date)
            VALUES(?, ?, ?, ?);
        `
        await db.run(userstransactionsQuery, [userId.id, amount, category, date]);
        response.status(200);
        response.send("Saved Successfully");
    }
    catch(e){
        response.send(e.message);
    }
})


//userstransactions API

app.get("/userform", JwtVerificationMiddleware, async (request, response) => {
    const {username} = request.payload;
    try{
        const userIdQuery = `
        SELECT id from users
        WHERE username=?;
        `
        const userId = await db.get(userIdQuery, [username])

        const userstransactionsData = `
            SELECT * FROM users_transactions
            WHERE users_id=?;
        `
        const res = await db.all(userstransactionsData, [userId.id]);
        response.send(res);
    }catch(e){
        response.send(e.message);
    }
})