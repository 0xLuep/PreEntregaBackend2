import envUtil from "./src/utils/env.util.js"
import express from "express"
import morgan from "morgan"
import cookieParser from "cookie-parser"
import session from "express-session"
//import sessionFileStore from "session-file-store"
import MongoStore from "connect-mongo"
import cors from "cors"
import errorHandler from "./src/middlewares/errorHandler.mid.js"
import pathHandler from "./src/middlewares/pathHandler.mid.js"
import indexRouter from "./src/routers/index.router.js"
import dbConnect from "./src/utils/dbConnect.util.js"
import argsUtil from "./src/utils/args.util.js"


// server
const server = express()
const port = envUtil.PORT
const ready = () => {
    console.log("server ready on port " + port)
    if (argsUtil.persistence === 'mongo') { 
        dbConnect()
    }
}
server.listen(port, ready)

// middlewares
server.use(express.json());
server.use(express.urlencoded({ extended: true }));
server.use(express.static('public'))
server.use(morgan("dev"));
// configuración de cookies
server.use(cookieParser(envUtil.SECRET_KEY))
server.use(cors({
    origin: true,
    //origin: 'www.miaplicationfront.com'
    credentials: true
}))


// configuración de session con memory
/*server.use(session({
    secret: 'envUtil.SECRET_KEY',
    resave: true,
    saveUninitialized: true,
    cookie: { maxAge: 60000 }
})) */

// configuración de session con file storage
/*const FileStore = sessionFileStore(session)
server.use(session({
    secret: 'envUtil.SECRET_KEY',
    resave: true,
    saveUninitialized: true,
    store: new FileStore({ path: "./src/data/fs/sessions", ttl: 10, retries: 2 })
})) */

// configuración de session con mongo storage
server.use(session({
    secret: 'envUtil.SECRET_KEY',
    resave: true,
    saveUninitialized: true,
    store: new MongoStore({ mongoUrl: envUtil.MONGO_LINK, ttl: 60*60 })
}))

//routers
server.use(indexRouter);
server.use(errorHandler);
server.use(pathHandler);