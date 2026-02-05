import mongoose from "mongoose";
import dotenv from "dotenv"
dotenv.config()//export a function to connects to db
const database = () => {
    mongoose.connect(process.env.URL)
        .then(() => {
            console.log('Connectd to MongoDB')
        })
        .catch((err) => {
            console.log('Failed to connect')
        })
}
export default database