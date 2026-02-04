import express from "express";
import cors from "cors";
import db from "./utils/databash.js"
import authRouter from "./routes/auth.route.js";
import cookieParser from "cookie-parser";

db();
const app = express();

app.use(
    cors({
        origin: "<http://localhost:3000>",
        credentials: true,
        methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
        allowHeaders: ['Content-Type', 'Authorization']
    })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


app.get("/", (req, res) => {
    res.send("Hello World!");
})
app.use("/api/v1/auth", authRouter);



app.listen(3000, () => {
    console.log("Server is running on port 3000");
});