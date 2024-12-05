import { model, Schema } from "mongoose";

const collection = 'users'

const schema = new Schema({
    name: { type: String },
    email: { type: String, required: true, index: true, unique: true },
    password: { type: String, required: true},
    role: { type: String, default: 'USER', enum: ['USER', 'ADMIN', 'PREM'] },
    verifyUser: { type: Boolean, default: false },
    verifyCode: { type: String, default: "0" }
})

const User = model(collection, schema)

export default User