import { Router } from "express";
import { readById } from "../../data/mongo/managers/user.manager.js";
import passport from "../../middlewares/passport.mid.js";
import { verifyTokenUtil } from "../../utils/token.util.js";

const sessionsRouter = Router()

sessionsRouter.post('/register', passport.authenticate('register', { session: false }), register)
sessionsRouter.post('/login', passport.authenticate('login', { session: false }), login)
sessionsRouter.post('/signout', signout)
sessionsRouter.post('/online', onlineToken)
sessionsRouter.post('/profile', currentProfile)
// /api/sessions/google va a llamar a la pantalla de consentimiento y se encarga de autenticar en google
sessionsRouter.post('/google', passport.authenticate('google', {scope: ['email', 'profile']}))
// /api/sessions/google/cb va a llamar a la estrategia encargada de register/login con google
sessionsRouter.post('/google/cb', passport.authenticate('google', { session: false }), google)

export default sessionsRouter


async function register(req, res, next) {
    try {
        const user = req.user
        return res.status(201).json({ message: `${user.email} REGISTERED` })
    } catch (error) {
        return next(error)
    }
}

async function login(req, res, next) {
    try {
        const message = 'USER LOGGED IN'
        //const user = req.user
        //return res.status(200).json({ message, user_id: user._id })
        return res.status(200).json({ message, token: req.token })
    } catch (error) {
        return next(error)
    }
}

function signout(req, res, next) {
    try {
        const { user_id } = req.session
        req.session.destroy()
        const message = 'USER SIGNED OUT'
        return res.status(200).json({ message, user_id })
    } catch (error) {
        return next(error)
    }
}

async function online(req, res, next) {
    try {
        const { user_id } = req.session
        const user = await readById(user_id)
        if (req.session.user_id) {
            return res.status(200).json({ message: `${user.email.toUpperCase()} IS ONLINE`, online: true })
        }
        return res.status(401).json({ message: 'USER IS NOT ONLINE', online: false })
    } catch (error) {
        return next(error)
    }
}

function google(req, res, next) {
    try {
        //const user = req.user
        //return res.status(200).json({ menssage: 'USER LOGGED IN', user_id: user._id})
        return res.status(200).json({ menssage: 'USER LOGGED IN', token: req.token})
    } catch (error) {
        return next(error)
    }
}

async function onlineToken(req,res,next) {
    try {
        const { token } = req.headers
        const data = verifyTokenUtil(token)
        const user = await readById(data.user_id)
        if (user) {
            return res.status(200).json({ message: `${user.email.toUpperCase()} IS ONLINE`, online: true })
        } else {
            return res.status(401).json({ message: 'USER IS NOT ONLINE', online: false })
        }
    } catch (error) {
        return next(error)
    }
}

async function currentProfile(req, res, next) {
    try {
        const { token } = req.headers
        const data = verifyTokenUtil(token)
        const user = await readById(data.user_id)
        if (user) {
            delete user.password
            return res.status(200).json({ user })
        } 
    } catch (error) {
        next(error)
    }
}