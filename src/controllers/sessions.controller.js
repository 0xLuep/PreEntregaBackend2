import { readById, readByEmail, update } from "../data/mongo/managers/users.manager.js";
import { verifyTokenUtil } from "../utils/token.util.js";

async function register(req, res) {
    const { _id } = req.user;
    const message = 'User Registered!';
    return res.json201(_id, message);
}

async function login(req, res) {
    const { token } = req.user;
    const opts = { maxAge: 60 * 60 * 24 * 7, httpOnly: true };
    const message = "User logged in!";
    const response = "OK";
    return res.cookie("token", token, opts).json200(response, message);
}

function signout(req, res) {
    const message = "User signed out!";
    const response = "OK";
    return res.clearCookie("token").json200(response, message);
}

async function online(req, res) {
    const { user_id } = req.session;
    const one = await readById(user_id);
    if (req.session.user_id) {
        const message = `${one.email} is online!`;
        const response = true;
        return res.json200(response, message);
    } else {
        const message = "User is not online!";
        return res.json400(message);
    }
}

function google(req, res) {
    return res.status(200).json({ message: "USER LOGGED IN", token: req.token });
}

async function onlineToken(req, res) {
    const { token } = req.headers
    const data = verifyTokenUtil(token)
    const user = await readById(data.user_id)
    if (user) {
        const message = `${user.email.toUpperCase()} IS ONLINE!`;
        const response = true
        return res.json200(response, message);
    } else {
        const message = "NOT ONLINE";
        const response = false
        return res.json200(response, message);
    }
}

async function currentProfile(req, res) {
    const { token } = req.headers
    const data = verifyTokenUtil(token)
    const user = await readById(data.user_id)
    if (user) {
        delete user.password
        //return res.status(200).json({ user })
        return res.json200(user, null);
    } else {
        const message = "NOT LOGGED";
        return res.json400(message);
    }
}

async function verify(req, res) {
    const { email, verifyCode } = req.body
    const user = await readByEmail(email)
    const verifyCodeFromDataBase = user.verifyCode
    if (verifyCodeFromDataBase === verifyCode ) {
        await update(user._id, { verify: true })
        const message = 'User verified'
        return res.json200('OK', message)
    }
    return res.json401()
}

export { register, login, signout, online, google, onlineToken, currentProfile, verify };