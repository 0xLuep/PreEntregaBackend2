import CustomRouter from "../../utils/CustomRouter.util.js";
import passportCb from "../../middlewares/passportCb.mid.js";
import { register, login, signout, onlineToken, currentProfile, google, verify } from "../../controllers/sessions.controller.js";


class SessionsApiRouter extends CustomRouter {
    constructor() {
        super();
        this.init();
    }
    init = () => {
        this.create('/register', ['PUBLIC'], passportCb('register'), register);
        this.create('/login', ['PUBLIC'], passportCb('login'), login);
        this.create('/signout', ['USER', 'ADMIN'], passportCb('signout'), signout);
        this.create('/online', ['USER', 'ADMIN'], passportCb('online'), onlineToken);
        this.create('/profile', ['USER', 'ADMIN'], passportCb('online'), currentProfile);
        this.create('/verify', ['PUBLIC'], verify)
        // /api/sessions/google va a llamar a la pantalla de consentimiento y se encarga de autenticar en google
        this.read('/google', ['PUBLIC'], passportCb('google', { scope: ['email', 'profile'] }));
        // /api/sessions/google/cb va a llamar a la estrategia encargada de register/login con google
        this.read('/google/cb', ['PUBLIC'], passportCb('google'), google);
    };
}

const sessionsRouter = new SessionsApiRouter();
export default sessionsRouter.getRouter();