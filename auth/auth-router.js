const express = require("express")
const bcrypt = require("bcryptjs")
// 1) install and import jsonwebtoken
const jwt = require( "jsonwebtoken" )
const Users = require("../users/users-model")
const restrict = require("../middleware/restrict")

const router = express.Router()

router.post("/register", async (req, res, next) => {
	try {
		const { username } = req.body
		const user = await Users.findBy({ username }).first()

		if (user) {
			return res.status(409).json({
				message: "Username is already taken",
			})
		}

		res.status(201).json(await Users.add(req.body))
	} catch(err) {
		next(err)
	}
})

router.post("/login", async (req, res, next) => {
	const authError = {
		message: "Invalid Credentials",
	}

	try {
		const user = await Users.findBy({ username: req.body.username }).first()
		if (!user) {
			return res.status(401).json(authError)
		}

		// since bcrypt hashes generate different results due to the salting,
		// we rely on the magic internals to compare hashes rather than doing it
		// manually with "!=="
		const passwordValid = await bcrypt.compare(req.body.password, user.password)
		if (!passwordValid) {
			return res.status(401).json(authError)
		}

		// creates a new session for the user and saves it in memory as a cookie.
		// it's this easy since we're using `express-session`
		// req.session.user = user
		// 2) instead of starting session, generate token
		const tokenPayload = {
			userId: user.id,
			userRole: "admin" //this would normally come from database, faking with hard coded string
		}
		// 8) remove token and send as a cookie
		res.cookie( "token", jwt.sign( tokenPayload, process.env.JWT_SECRET ) )
		res.json({
			message: `Welcome ${user.username}!`,
			// 3) create token with a secret string and send with json body
			// token: jwt.sign( tokenPayload, "secretStringNotForClient" )
			// token: jwt.sign( tokenPayload, process.env.JWT_SECRET ) <--- commented out for #8)
			// 4) install and create .env file, add secret string to JWT_SECRET value, and add dependency option to server script in package.json
			// 5) replace secret string with process.env.JWT_SECRET
		})
	} catch(err) {
		next(err)
	}
})


module.exports = router