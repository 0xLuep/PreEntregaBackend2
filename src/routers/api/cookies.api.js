// ESTE ARCHIVO NO ESTÁ EN USO

import { Router } from "express";

const cookiesRouter = Router()

cookiesRouter.post('/', (req, res, next) => {
    try {
        // para la modificación de una cookie, se sobre-escribe la misma con el mismo método de creación de cookie
        const message = 'COOKIE SETEADA O MODIFICADA'
        return res
            .status(201)
            .cookie('modo', 'oscuro', { signed: true })
            .cookie('rolDeUsuario', 'admin', { signed: true, maxAge: 10000 })
            .json({ message })
    } catch (error) {
        return next(error)
    }
})

cookiesRouter.get('/', (req, res, next) => {
    try {
        const cookie = req.cookies
        const response = cookie
        const message = 'COOKIES LEIDA'
        return res.status(200).json({ response, message })
    } catch (error) {
        return next(error)
    }
})

cookiesRouter.delete('/:cookieName', (req, res, next) => {
    try {
        const message = 'COOKIE DESTROYED'
        const cookieName = req.params.cookieName
        return res
            .status(200)
            .clearCookie(cookieName)
            .json({ message })
    } catch (error) {
        return next(error)
    }
})


export default cookiesRouter