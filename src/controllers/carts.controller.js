import { createService, readService, updateService, destroyService } from "../services/carts.service.js"

async function createCart(req, res) {
    const message = "CART CREATED";
    const data = req.body;
    const response = await createService(data);
    return res.json201(response, message);
}

async function readCartsFromUser(req, res) {
    const { user_id } = req.params;
    const message = "CARTS FOUND";
    const response = await readService({ user_id });
    return res.json200(response, message);
}

async function updateCart(req, res) {
    const { id } = req.params;
    const data = req.body;
    const message = "CART UPDATED";
    const response = await updateService(id, data);
    return res.json200(response, message);
}

async function destroyCart(req, res) {
    const { id } = req.params;
    const message = "CART DELETED";
    const response = await destroyService(id);
    return res.json200(response, message);
}


export { createCart, readCartsFromUser, updateCart, destroyCart };