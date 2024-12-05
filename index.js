import "dotenv/config.js"
import express from "express"
import morgan from "morgan"
import cookieParser from "cookie-parser"
import session from "express-session"
//import sessionFileStore from "session-file-store"
import MongoStore from "connect-mongo"
import errorHandler from "./src/middlewares/errorHandler.mid.js"
import pathHandler from "./src/middlewares/pathHandler.mid.js"
import indexRouter from "./src/routers/index.router.js"
import dbConnect from "./src/utils/dbConnect.util.js"



// server
const server = express()
const port = process.env.PORT
const ready = () => {
    console.log("server ready on port " + port)
    dbConnect()
}
server.listen(port, ready)

// middlewares
server.use(express.json());
server.use(express.urlencoded({ extended: true }));
server.use(express.static('public'))
server.use(morgan("dev"));
// configuración de cookies
server.use(cookieParser(process.env.SECRET_KEY))


// configuración de session con memory
/*server.use(session({
    secret: 'process.env.SECRET_KEY',
    resave: true,
    saveUninitialized: true,
    cookie: { maxAge: 60000 }
})) */

// configuración de session con file storage
/*const FileStore = sessionFileStore(session)
server.use(session({
    secret: 'process.env.SECRET_KEY',
    resave: true,
    saveUninitialized: true,
    store: new FileStore({ path: "./src/data/fs/sessions", ttl: 10, retries: 2 })
})) */

// configuración de session con mongo storage
server.use(session({
    secret: 'process.env.SECRET_KEY',
    resave: true,
    saveUninitialized: true,
    store: new MongoStore({ mongoUrl: process.env.MONGO_LINK, ttl: 60*60 })
}))

//routers
server.use(indexRouter);
server.use(errorHandler);
server.use(pathHandler);