import { Router } from "express";
import usersApiRouter from "./users.api.js";
import cookiesRouter from "./cookies.api.js";
import sessionsRouter from "./sessions.api.js";


const apiRouter = Router()

apiRouter.use("/users", usersApiRouter)
apiRouter.use("/cookies", cookiesRouter)
apiRouter.use("/sessions", sessionsRouter)


export default apiRouter