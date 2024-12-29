import { model, Schema } from "mongoose";

const collection = "products"
// ingles
// plural
// minusculas
// representativo del recurso
const schema = new Schema({
    title: { type: String, required: true, index: true },
    price: { type: Number, default: 10 },
    stock: { type: Number, default: 10 },
    category: { type: String, enum: ["remera","buzo","pantalon","zapatilla"], default: "noCategory"}
})

const Product = model(collection, schema)
export default Product