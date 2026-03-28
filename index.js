import express from "express";
import cors from "cors";
import db from "./utils/database.js"
import authRouter from "./routes/auth.route.js";
import cookieParser from "cookie-parser";
import http from "http";

import { Server } from "socket.io";
import { socketHandler } from "./sockets/socket.js";
import chatRouter from "./routes/chat.route.js";
import aiRouter from "./routes/ai.route.js";
import taskRouter from "./routes/test.router.js";
import questRouter from "./routes/Quest.route.js";



db();
const app = express();



app.use(
    cors({
        origin: "*", // Allow all origins for easier debugging on physical devices
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
        origin: "*",  
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
app.use("/api/v1/ai", aiRouter);
app.use("/api/v1/task", taskRouter);
app.use("/api/v1/quests", questRouter);



server.listen(3001, '0.0.0.0', () => {
    console.log("Server is running on port 3001 and accessible on the local network");
    console.log("READY FOR AUTH REQUESTS: http://0.0.0.0:3001/api/v1/auth/...");
});