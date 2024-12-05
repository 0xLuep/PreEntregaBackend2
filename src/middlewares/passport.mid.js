import passport from "passport"
import { Strategy as LocalStrategy } from "passport-local"
import { Strategy as GoogleStrategy } from "passport-google-oauth2"
import { create, readByEmail } from "../data/mongo/managers/user.manager.js"
import { createHashUtil, verifyHashUtil } from "../utils/hash.util.js"
import { createTokenUtil } from "../utils/token.util.js"
const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, BASE_URL } = process.env


passport.use('register', new LocalStrategy(
    { passReqToCallback: true, usernameField: 'email' },
    async (req, email, password, done) => {
        try {
            if (!email || !password) {
                //lo hace automatico, no hace falta definir nada acá
            }
            const one = await readByEmail(email)
            if (one) {
                const error = new Error('USER ALREADY EXIST')
                error.statusCode=400
                return done(error)
            }
            req.body.password = createHashUtil(password)
            const data = req.body
            const user = await create(data)
            return done(null, user)
        } catch (error) {
            return done(error)
        }
    }
))

passport.use('login', new LocalStrategy(
    { passReqToCallback: true, usernameField: 'email' },
    async (req, email, password, done) => {
        try {
            const user = await readByEmail(email)
            if (!user) {
                const error = new Error('INVALID EMAIL')
                error.statusCode = 401
                return done(error)
            }
            const dbPassword = user.password
            const verify = verifyHashUtil(password, dbPassword)
            if (!verify) {
                const error = new Error('INVALID CREDENTIALS')
                error.statusCode = 401
                return done(error)
            }
            
            //req.session.role = user.role
            //req.session.user_id = user._id
            
            req.token = createTokenUtil({ role: user.role, user_id: user._id})
            
            return done(null, user)
        } catch (error) {
            return done(error)
        }
    }
))

passport.use('google', new GoogleStrategy(
    { clientID: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET, passReqToCallback: true, callbackURL: `${BASE_URL}sessions/google/cb`},
    async (req, accessToken, refreshToken, profile, done) => {
        try {
            // tomo el id y la foto del usuario de google
            const { id, picture } = profile
            // como estrategia de terceros no se suele registrar al usuario pro su email sino por su identificador en la base del tercero, esto es debido a que si utilizo
            // el email, si o si necesito la contraseña, la cual el tercero no nos la envía (google)
            let user = await readByEmail(id)
            // si el usuario existe, logea, sino lo registra, y luego lo logea
            if (!user) {
                user = await create({ email: id, photo: picture, password: createHashUtil(id) })
            }
            
            //req.session.role = user.role
            //req.session.user_id = user._id
            
            req.token = createTokenUtil({ role: user.role, user_id: user._id})
            
            return done(null, user)
        } catch (error) {
            return done(error)
        }
    }
))


export default passport