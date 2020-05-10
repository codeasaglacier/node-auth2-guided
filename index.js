// How do we protect user's passwords when we store them in the database
// 	Hashing

// 	What is hashing and how is it different from encryption
// 	Chopping up data to produce a mixed string, turning it into a mix of random letters and numbers
// 	One way operation, can't be undone.
// 	Encryption can be reversed with a key

// How is Authentication ( AuthN ) different from Authorization ( AuthZ )?
// 	AuthN determines who the user is, AuthZ determines what the user is allowed to do

// What is salting
// 	A random string at the front or ens of your string to be hashed that gets hashed with the original string
// 	Prevents identical passwords from having the same hash, prevents the use of rainbow tables

// What is a session
// 	A virtual "ticket stub" stored in the database that has information about the authN

// Whats a cookie
// 	A way for clients to persist a small amount of data stored in the cookie jar on the client side
// 	Every subsequent request sends this data

// Horizontal Scaling 
// 	Using multiple servers in parallel to handle a lot of traffic
// 	Each server has its own memory, there must be a central store for sessions data

// JSON Web Tokens
// 	Similar to a preauthorized keycard, a way for two parties to share JSON data securely without any shared state
// 	Uses cryptographic hashing to digitally sign the data to make sure it wasn't tampered with
// 	A long string that consists of three chunks
//		Header    - Base64 ( numbers and letters ) encoded object that contains two values, Algorithm: 
// 								"numbersandletters" and Type: "JWT" 
// 		Payload		- Data you want to pass back and forth, known as Claims. Also Base64 encoded
// 		Signature	- A hash of the header and payload and a secret string

// JWT Auth Flow
//		Client sends credentials to server ( Login )
//		Server verifies credentials ( Look up user, check password hash )
//		Server creates a JWT for client
//		Server sends back the JWT as a header
//		Client stores the JWT in localstorage
//		Client sends JWT on every subsequent request
//		Server verifies the JWT is valid by checking the signature ( no state required )
//		Server provides access to the resource
//		Nearly impossible to log the user out
//			Give JWT expiration dates
//			Create blacklist of JWTs that have logged out
//			Use JWTs alongside sessions and use the JWT to store the session id 

const express = require("express")
const helmet = require("helmet")
const cors = require("cors")
const session = require("express-session")
// 9)install and import cookie-parser
const cookieParser = require( "cookie-parser" )
const authRouter = require("./auth/auth-router")
const usersRouter = require("./users/users-router")

const server = express()
const port = process.env.PORT || 5000

server.use(cors())
server.use(helmet())
server.use(express.json())
// 10) call cookie parser with server.use and get rid of server.use( session )
server.use( cookieParser() )
// server.use(session({
// 	name: "sess", // overwrites the default cookie name, hides our stack better
// 	resave: false, // avoid recreating sessions that have not changed
// 	saveUninitialized: false, // GDPR laws against setting cookies automatically
// 	secret: "keep it secret, keep it safe", // cryptographically sign the cookie
// }))

server.use("/auth", authRouter)
server.use("/users", usersRouter)

server.get("/", (req, res, next) => {
	res.json({
		message: "Welcome to our API",
	})
})

server.use((err, req, res, next) => {
	console.log(err)
	res.status(500).json({
		message: "Something went wrong",
	})
})

server.listen(port, () => {
	console.log(`Running at http://localhost:${port}`)
})
