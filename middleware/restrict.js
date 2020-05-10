// 6)import jwtwebtoken
const jwt = require( "jsonwebtoken" )

// 12) add a parameter of role with default of normal
function restrict( role = "normal" ) {
	return async (req, res, next) => {
		const authError = {
			message: "Invalid credentials",
		}

		try {
			// console.log( req.headers )
			// express-session will automatically get the session ID from the cookie
			// header, and check to make sure it's valid and the session for this user exists.
			// 7) instead of a session check, use a token check
			// if (!req.session || !req.session.user) {
			// 	return res.status(401).json(authError)
			// }
			// const token = req.headers.authorization <--- commented out for #11)
			// 11) replace req.headers.authorization with req.cookies.token
			const token = req.cookies.token
			if ( !token ) {
				// you must return from the request if sending a response early
				// ( with an error, for example )
				// otherwise it will try to send another response after one was already sent
				return res.status( 401 ).json( authError )
			}

			//call jwt.verify with token and secret key
			jwt.verify( token, process.env.JWT_SECRET, ( err, decodedPayload ) => {
				// 13) add a check for userRole not being the same as role
				if ( err || decodedPayload.userRole !== role ) {
					return res.status( 401 ).json( authError )
				}
				//assign req.token to decodedPayload
				req.token = decodedPayload
				next()
			} )
		} catch(err) {
			next(err)
		}
	}
}

module.exports = restrict