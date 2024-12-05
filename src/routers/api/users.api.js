import { Router } from "express";
import { read, create, update, destroy } from "../../data/mongo/managers/user.manager.js";

const usersApiRouter = Router()

usersApiRouter.post("/", async (req, res, next) => {
    try {
        const message = 'USER CREATE'
        const data = req.body
        const response = await create(data)
        return res.status(201).json({ response, message })
    } catch (error) {
        return next(error)
    }
})

usersApiRouter.get("/", async (req, res, next) => {
    try {
        const message = `USERS FOUND`
        const response = await read()
        return res.status(200).json({ response, message })
    } catch (error) {
        return next(error)
    }
})

usersApiRouter.put("/:id", async (req, res, next) => {
    try {
        const message = 'USER UPDATED'
        const userId = req.params.id
        const data = req.body
        const response = await update(userId, data)
        return res.status(200).json({ response, message })
    } catch (error) {
        return next(error)
    }
})

usersApiRouter.delete("/:id", async (req, res, next) => {
    try {
        const message = 'USER DELETED'
        const userId = req.params.id
        const response = await destroy(userId)
        return res.status(200).json({ response, message })
    } catch (error) {
        return next(error)
    }
})


export default usersApiRouter