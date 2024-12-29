import passport from "passport"
import crypto from "crypto"
import { Strategy as LocalStrategy } from "passport-local"
import { Strategy as GoogleStrategy } from "passport-google-oauth2"
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt"
import { create, readByEmail, readById, update } from "../data/mongo/managers/users.manager.js"
import { createHashUtil, verifyHashUtil } from "../utils/hash.util.js"
import { createTokenUtil } from "../utils/token.util.js"
import envUtil from "../utils/env.util.js"
import { sendVerifyEmail } from "../utils/nodemailer.util.js"
const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, BASE_URL } = envUtil


passport.use('register', new LocalStrategy(
    { passReqToCallback: true, usernameField: 'email', passwordField: 'password' },
    async (req, email, password, done) => {
        try {
            if (!email || !password) {
                //lo hace automatico, no hace falta definir nada acá
            }
            const one = await readByEmail(email)
            if (one) {
                const info = { message: "USER ALREADY EXISTS", statusCode: 401 };
                return done(null, false, info);
            }
            const hashedPassword = createHashUtil(password)
            const verifyCode = crypto.randomBytes(12).toString("hex")
            const user = await create({
                email,
                password: hashedPassword,
                name: req.body.name || 'Default Name',
                verifyCode
            })
            await sendVerifyEmail({ to: email, verifyCode })
            return done(null, user)
        } catch (error) {
            return done(error)
        }
    }
))

passport.use('login', new LocalStrategy(
    { usernameField: 'email' },
    async ( email, password, done) => {
        try {
            const user = await readByEmail(email)
            if (!user) {
                const info = { message: "INVALID EMAIL", statusCode: 401 };
                return done(null, false, info);
            }
            if (!user.verify) {
                const info = { message: 'Please verify your account' }
                return done(null, false, info)
            }
            const dbPassword = user.password
            const verify = verifyHashUtil(password, dbPassword)
            if (!verify) {
                const info = { message: "INVALID CREDENTIALS", statusCode: 401 };
                return done(null, false, info);
            }
            
            //req.session.role = user.role
            //req.session.user_id = user._id
            
            user.token = createTokenUtil({ role: user.role, user_id: user._id})
            await update(user._id, { isOnline: true })
            
            return done(null, user)
        } catch (error) {
            return done(error)
        }
    }
))

passport.use('online', new JwtStrategy(
    { jwtFromRequest: ExtractJwt.fromExtractors([req=>req?.cookies?.token]), secretOrKey: envUtil.SECRET_KEY },
    async (data, done) => {
        try {
            const { user_id } = data;
            const user = await readById(user_id);
            const { isOnline } = user;
            if (!isOnline) {
                const info = { message: "USER IS NOT ONLINE", statusCode: 401 };
                return done(null, false, info);
            }
            return done(null, user);
        } catch (error) {
            return done(error)
        }
    }
))

/*passport.use('signout', new LocalStrategy(
    { passReqToCallback: true },
    (req, done) => {
        try {
            const token = req.token
            if (!token) {
                const error = new Error('USER NOT LOGGED')
                error.statusCode = 401
                return done(error)
            }
            delete req.token
            return done(null, null)
        } catch (error) {
            return done(error)
        }
    }
))*/

passport.use('signout', new JwtStrategy(
    { jwtFromRequest: ExtractJwt.fromExtractors([req=>req?.cookies?.token]), secretOrKey: envUtil.SECRET_KEY },
    async (data, done) => {
        try {
            const { user_id } = data
            await update(user_id, { isOnline: false })
            return done(null, { user_id: null })
        } catch (error) {
            done(error)
        }
    }
))


/*passport.use('admin', new LocalStrategy(
    { passReqToCallback: true },
    async (req, done) => {
        try {
            const token = req.token
            const { role, user_id } = verifyTokenUtil(token)
            if (role !== 'ADMIN') {
                const error = new Error('UNAUTHORIZED');
                error.statusCode = 403;
                return done(error);
            }
            const user = await readById(user_id);
            user.password = null
            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }
))*/

passport.use('admin', new JwtStrategy(
    { jwtFromRequest: ExtractJwt.fromExtractors([req=>req?.cookies?.token]), secretOrKey: envUtil.SECRET_KEY },
    async (data, done) => {
        try {
            const { user_id, role } = data
            if (role !== 'ADMIN') {
                const info = { message: "NOT AUTHORIZE", statusCode: 403 };
                return done(null, false, info);
            }
            const user = await readById(user_id)
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