import { connect } from "mongoose";

async function dbConnect() {
    try {
        connect(process.env.MONGO_LINK)
        console.log("mongodb connected")
    } catch {
        console.log(error);
    }
}

export default dbConnect