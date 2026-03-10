import taskModel from "../models/task.model.js";


export const addTaskController = async (req, res) => {

    const { title, description, due_date, priority, category } = req.body;

    if (!title || !description || !due_date || !priority || !category) {
        return res.status(400).json({ message: "All fields are required" });
    }

    try {

        const task = await taskModel.create({
            title,
            description,
            due_date,
            priority,
            category,
            user: req.user.id
        });

        res.status(201).json({
            success: true,
            task
        });

    } catch (error) {

        console.error("Error adding task:", error);

        res.status(500).json({
            message: "Internal server error"
        });
    }
};

export const updateTaskController = async (req, res) => {

    const { id, title, description, due_date, priority, category, status } = req.body;

    if (!id) {
        return res.status(400).json({ message: "Task id is required" });
    }

    try {

        const task = await taskModel.findOneAndUpdate(
            { _id: id, user: req.user.id },
            { title, description, due_date, priority, category, status },
            { new: true }
        );

        if (!task) {
            return res.status(404).json({
                message: "Task not found"
            });
        }

        res.status(200).json({
            success: true,
            task
        });

    } catch (error) {

        console.error("Error updating task:", error);

        res.status(500).json({
            message: "Internal server error"
        });
    }
};

export const deleteTaskController = async (req, res) => {

    const { id } = req.body;

    if (!id) {
        return res.status(400).json({
            message: "Task id is required"
        });
    }

    try {

        const task = await taskModel.findOneAndDelete({
            _id: id,
            user: req.user.id
        });

        if (!task) {
            return res.status(404).json({
                message: "Task not found"
            });
        }

        res.status(200).json({
            success: true,
            message: "Task deleted successfully"
        });

    } catch (error) {

        console.error("Error deleting task:", error);

        res.status(500).json({
            message: "Internal server error"
        });
    }
};

export const getAllTasksController = async (req, res) => {

    try {

        const tasks = await taskModel
            .find({ user: req.user.id })
            .sort({ createdAt: -1 });

        res.status(200).json({
            success: true,
            tasks
        });

    } catch (error) {

        console.error("Error fetching tasks:", error);

        res.status(500).json({
            message: "Internal server error"
        });
    }
};

export const markAsCompletedController = async (req, res) => {

    const { id } = req.body;

    if (!id) {
        return res.status(400).json({
            message: "Task id is required"
        });
    }

    try {

        const task = await taskModel.findOneAndUpdate(
            { _id: id, user: req.user.id },
            { status: "completed" },
            { new: true }
        );

        if (!task) {
            return res.status(404).json({
                message: "Task not found"
            });
        }

        res.status(200).json({
            success: true,
            task
        });

    } catch (error) {

        console.error("Error marking task as completed:", error);

        res.status(500).json({
            message: "Internal server error"
        });
    }
};