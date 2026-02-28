import express from "express";
import cors from "cors";
import db from "./utils/database.js"
import authRouter from "./routes/auth.route.js";
import cookieParser from "cookie-parser";
import http from "http";

import { Server } from "socket.io";
import { socketHandler } from "./sockets/socket.js";
import chatRouter from "./routes/chat.route.js";


db();
const app = express();



app.use(
    cors({
        origin: ["http://localhost:3000", "http://localhost:3001"],
        credentials: true,
        methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
        allowHeaders: ['Content-Type', 'Authorization']
    })
);


// create HTTP server
const server = http.createServer(app);

// create socket server
const io = new Server(server, {
    cors: {
        origin: ["http://localhost:3000", "http://localhost:3001"],   // for dev (later restrict)
        credentials: true,
    },
});

socketHandler(io);


app.set("trust proxy", true)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


app.get("/", (req, res) => {
    res.send("Hello World!");
})
app.use("/api/v1/auth", authRouter);
app.use("/api/v1/chat", chatRouter);



server.listen(3000, () => {
    console.log("Server is running on port 3000");
});