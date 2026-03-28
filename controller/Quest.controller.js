import Quest from "../models/Quest.model.js";
import User from "../models/User.model.js";
import { generateAiResponse } from "../config/aiService.js";

export const generateDailyQuest = async (req, res) => {
    try {
        const userId = req.user._id;
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Check if user already has an active daily quest
        const existingQuest = await Quest.findOne({
            userId,
            status: "active",
            type: "daily",
            createdAt: { $gte: new Date().setHours(0, 0, 0, 0) }
        });

        if (existingQuest) {
            return res.status(200).json({
                success: true,
                quest: existingQuest,
                message: "Quest already exists for today."
            });
        }

        const prompt = `
            You are the System Administrator from Solo Leveling. Generate a Daily Quest for a Level ${user.level} player.
            THEME: Physical Training and Exercises.
            
            Current Difficulty:
            - If Level < 5: Focus on LIGHT exercises (e.g., stretching, 5-10 pushups, short walks, basic squats).
            - If Level 5-10: Focus on MODERATE training (e.g., 20+ pushups, 2km jog, lunges).
            - If Level > 10: INTENSE workouts (e.g., HIIT sessions, 5km+ runs, high-rep calisthenics).

            The player stats are: HP ${user.hp}/${user.maxHp}, Strength ${user.strength}, Agility ${user.agility}.
            
            Difficulty Scaling Table:
            - A Level ${user.level} player needs ${user.level * 1000} EXP to reach the next level.
            - Rewards should be exactly 20-25% of the current level's total EXP to ensure steady progression.
            - Objectives must be specific and challenging (e.g., instead of 'Run', use 'Run 3km at a steady 6:00 min/km pace').
            
            Return ONLY a JSON object. IMPORTANT: Do NOT include comments, do NOT include '+' signs before numbers, and do NOT include any extra text.
            Structure:
            {
                "title": "A short, cool training title (e.g., 'Morning Conditioning')",
                "description": "Intimidating Administrator description",
                "timeLimit": number,
                "objectives": [
                    { "text": "exercise", "target": number }
                ],
                "verificationQuestions": [
                    { "question": "Provide a HIGHLY DETAILED question about the physical execution of the exercise." },
                    { "question": "Provide a HIGHLY DETAILED question about the environment and psychological state during the trial." },
                    { "question": "Provide a HIGHLY DETAILED question about the physiological recovery and fatigue levels." }
                ],
                "rewards": { 
                    "exp": number, 
                    "coins": number,
                    "statPoints": number,
                    "stats": { "strength": 0, "stamina": 0, "agility": 0, "intelligence": 0, "sense": 0, "mana": 0 }
                },
                "penalty": { 
                    "hpLoss": number,
                    "stats": { "strength": 0, "stamina": 0, "agility": 0, "intelligence": 0, "sense": 0, "mana": 0 }
                }
            }
            Objectives and rewards MUST scale strictly with Level ${user.level}.
        `;

        const aiReply = await generateAiResponse(prompt);
        console.log("[QuestController] AI Raw Response:", aiReply);

        // Extract JSON from AI response (handle potential markdown formatting)
        let jsonStr = aiReply.replace(/```json/g, "").replace(/```/g, "").trim();

        // 1. Strip comments (e.g., // some explanation)
        jsonStr = jsonStr.replace(/\/\/.*$/gm, "");

        // 2. Remove '+' from numbers (AI often does +1 instead of 1)
        jsonStr = jsonStr.replace(/:\s*\+(\d+)/g, ": $1");

        // 3. Find the first { and last } to handle any extra text from AI
        const firstBrace = jsonStr.indexOf('{');
        const lastBrace = jsonStr.lastIndexOf('}');
        if (firstBrace !== -1 && lastBrace !== -1) {
            jsonStr = jsonStr.slice(firstBrace, lastBrace + 1);
        }

        let questData;
        try {
            questData = JSON.parse(jsonStr);
        } catch (parseError) {
            console.error("[QuestController] JSON Parse Error:", parseError);
            console.error("[QuestController] Cleaned JSON string:", jsonStr);
            throw new Error("Invalid AI response format");
        }

        const newQuest = await Quest.create({
            userId,
            ...questData,
            type: "daily",
            expiresAt: new Date().setHours(23, 59, 59, 999)
        });

        // Reset dailyQuestCompleted flag to allow the cycle to repeat
        if (user) {
            user.dailyQuestCompleted = false;
            await user.save();
        }

        res.status(201).json({
            success: true,
            quest: newQuest
        });

    } catch (error) {
        console.error("Generate Quest Error:", error);
        res.status(500).json({
            message: "System failed to generate quest.",
            error: error.message
        });
    }
};

export const getActiveQuests = async (req, res) => {
    try {
        const userId = req.user._id;
        const quests = await Quest.find({ userId, status: "active" }).sort({ createdAt: -1 });

        // Auto-Fail Check for Expired Quests
        const updatedQuests = [];
        const now = new Date();

        for (let quest of quests) {
            const timeLimitMs = (quest.timeLimit || 1440) * 60 * 1000;
            const startTime = new Date(quest.startedAt || quest.createdAt);

            if (now - startTime > timeLimitMs) {
                // Quest Expired -> Mark as Failed
                quest.status = "failed";
                await quest.save();

                // --- PENALTY LOGIC ---
                const user = await User.findById(userId);

                // Dynamic Penalty: 1-10% of maxExp
                const expPenalty = Math.floor(user.maxExp * (0.01 + Math.random() * 0.09));
                const coinPenalty = Math.floor(user.level * 10);

                user.exp = Math.max(0, user.exp - expPenalty);
                user.coins = Math.max(0, user.coins - coinPenalty);

                // Penalty scales with level: base penalty + (level * 2)
                const totalHpLoss = (quest.penalty.hpLoss || 10) + (user.level * 2);
                user.hp = Math.max(0, user.hp - totalHpLoss);

                // Stat Penalties
                if (quest.penalty.stats) {
                    Object.keys(quest.penalty.stats).forEach(stat => {
                        if (user[stat] !== undefined) {
                            user[stat] = Math.max(1, user[stat] - (quest.penalty.stats[stat] || 0));
                        }
                    });
                }

                await user.save();
            } else {
                updatedQuests.push(quest);
            }
        }

        res.status(200).json({ success: true, quests: updatedQuests });
    } catch (error) {
        console.error("Fetch Active Quests Error:", error);
        res.status(500).json({ message: "Failed to fetch active quests" });
    }
};

export const getCompletedQuests = async (req, res) => {
    try {
        const userId = req.user._id;
        const quests = await Quest.find({ userId, status: "completed" }).sort({ updatedAt: -1 });
        res.status(200).json({ success: true, quests });
    } catch (error) {
        res.status(500).json({ message: "Failed to fetch completed quests" });
    }
};

export const getFailedQuests = async (req, res) => {
    try {
        const userId = req.user._id;
        const quests = await Quest.find({ userId, status: "failed" }).sort({ updatedAt: -1 });
        res.status(200).json({ success: true, quests });
    } catch (error) {
        res.status(500).json({ message: "Failed to fetch failed quests" });
    }
};

export const completeQuest = async (req, res) => {
    try {
        const { questId } = req.params;
        const { answers } = req.body; // Expecting array of 5 answers
        const userId = req.user._id;

        const quest = await Quest.findOne({ _id: questId, userId, status: "active" });
        if (!quest) {
            return res.status(404).json({ message: "Active quest not found" });
        }

        if (!answers || answers.length < 1) {
            return res.status(400).json({ message: "Incomplete verification. Answers required." });
        }

        const user = await User.findById(userId);

        // --- ADMIN BYPASS ---
        // If any answer is exactly "admin", skip AI verification and approve.
        if (answers.some(a => a?.toLowerCase() === "admin")) {
            quest.status = "completed";
            await quest.save();

            // Mark user as having completed a quest today
            if (user) {
                user.dailyQuestCompleted = true;
                await user.save();
            }

            return res.status(200).json({
                success: true,
                message: "[ADMIN OVERRIDE]: Quest verified by Administrator authority.",
                isPassed: true,
                score: 5
            });
        }

        if (answers.length < 3) {
            return res.status(400).json({ message: "Incomplete verification. 3 detailed answers required." });
        }

        // --- AI VERIFICATION ---
        const verificationPrompt = `
            You are the System Administrator. A player (Level ${user.level}) is claiming completion of the quest: "${quest.title}".
            Quest Description: "${quest.description}"
            
            The player has provided the following 3 detailed answers to verification questions:
            ${quest.verificationQuestions.slice(0, 3).map((q, i) => `Q: ${q.question}\nA: ${answers[i] || "N/A"}`).join("\n\n")}
            
            Determine if the player actually completed the quest based on these answers. 
            Be strict but fair. If at least 3 answers are plausible and consistent with the physical/mental effort of the quest, approve it.
            Return ONLY a JSON object:
            {
                "approved": boolean,
                "reason": "Short explanation in Administrator persona",
                "score": number (0-5)
            }
        `;

        const aiResponse = await generateAiResponse(verificationPrompt);
        const jsonStr = aiResponse.replace(/```json/g, "").replace(/```/g, "").trim();
        const verificationResult = JSON.parse(jsonStr);

        if (!verificationResult.approved || verificationResult.score < 3) {
            return res.status(400).json({
                success: false,
                message: verificationResult.reason || "Quest verification failed. The System detects a lie.",
                score: verificationResult.score
            });
        }

        // --- SUCCESS LOGIC ---
        // REFACTOR: Do NOT apply rewards here. Only mark as completed.
        // The user must claim them in the Reward Screen.

        quest.status = "completed";
        await quest.save();

        // Mark user as having completed a quest today
        if (user) {
            user.dailyQuestCompleted = true;
            await user.save();
        }

        res.status(200).json({
            success: true,
            message: "Quest verified successfully. Claim your rewards in the Reward Hub.",
            isPassed: true,
            score: verificationResult.score
        });

    } catch (error) {
        console.error("Complete Quest Error:", error);
        res.status(500).json({ message: "Quest completion failed" });
    }
};

export const failQuest = async (req, res) => {
    try {
        const { questId } = req.params;
        const userId = req.user._id;

        const quest = await Quest.findOne({ _id: questId, userId, status: "active" });
        if (!quest) return res.status(404).json({ message: "Active quest not found" });

        quest.status = "failed";
        await quest.save();

        const user = await User.findById(userId);

        // Dynamic Penalty: 1-10% of maxExp
        const expPenalty = Math.floor(user.maxExp * (0.01 + Math.random() * 0.09));
        const coinPenalty = Math.floor(user.level * 10);

        user.exp = Math.max(0, user.exp - expPenalty);
        user.coins = Math.max(0, user.coins - coinPenalty);

        // Penalty scales with level: base penalty + (level * 2)
        const totalHpLoss = (quest.penalty.hpLoss || 10) + (user.level * 2);
        user.hp = Math.max(0, user.hp - totalHpLoss);

        // Stat Penalties
        if (quest.penalty.stats) {
            Object.keys(quest.penalty.stats).forEach(stat => {
                if (user[stat] !== undefined) {
                    user[stat] = Math.max(1, user[stat] - (quest.penalty.stats[stat] || 0));
                }
            });
        }

        await user.save();

        res.status(200).json({
            success: true,
            message: "Quest forfeited. Penalties applied.",
            penalty: {
                hpLoss: quest.penalty.hpLoss,
                expLoss: "EXP reduction applied",
                coinLoss: "Level-based coins deducted"
            }
        });
    } catch (error) {
        res.status(500).json({ message: "Failed to process quest failure" });
    }
};

export const claimQuestReward = async (req, res) => {
    try {
        const { questId } = req.params;
        const userId = req.user._id;

        const quest = await Quest.findOne({ _id: questId, userId });
        if (!quest) return res.status(404).json({ message: "Quest not found" });
        if (quest.status !== "completed") return res.status(400).json({ message: "Quest not completed" });
        if (quest.isClaimed) return res.status(400).json({ message: "Reward already claimed" });

        const user = await User.findById(userId);

        // Apply Rewards
        user.exp += (quest.rewards.exp || 0);
        user.coins += (quest.rewards.coins || 0);
        user.availableStatPoints += (quest.rewards.statPoints || 0);

        // Apply Direct Stat Rewards
        if (quest.rewards.stats) {
            Object.keys(quest.rewards.stats).forEach(stat => {
                if (user[stat] !== undefined) {
                    user[stat] += (quest.rewards.stats[stat] || 0);
                }
            });
        }

        // Level Up Logic
        let leveledUp = false;
        while (user.exp >= user.maxExp) {
            user.exp -= user.maxExp;
            user.level += 1;
            user.maxExp = user.level * 1000;
            user.maxHp += 100; // 20 HP increase per level
            user.maxMp += 50; // 10 MP increase per level
            user.hp = user.maxHp;
            user.mp = user.maxMp;
            leveledUp = true;
        }

        await user.save();
        quest.isClaimed = true;
        await quest.save();

        res.status(200).json({
            success: true,
            message: leveledUp ? `LEVEL UP! REACHED LEVEL ${user.level}.` : "Rewards claimed successfully.",
            user: {
                exp: user.exp,
                level: user.level,
                coins: user.coins,
                availableStatPoints: user.availableStatPoints
            }
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const assignStatPoint = async (req, res) => {
    try {
        const userId = req.user._id;
        const { stat } = req.body; // 'strength', 'stamina', etc.

        const user = await User.findById(userId);
        if (user.availableStatPoints <= 0) {
            return res.status(400).json({ message: "No stat points available" });
        }

        const validStats = ['strength', 'stamina', 'agility', 'intelligence', 'sense', 'mana'];
        if (!validStats.includes(stat)) {
            return res.status(400).json({ message: "Invalid attribute" });
        }

        user[stat] += 1;
        user.availableStatPoints -= 1;
        await user.save();

        res.status(200).json({
            success: true,
            message: `${stat.toUpperCase()} INCREASED!`,
            user: {
                [stat]: user[stat],
                availableStatPoints: user.availableStatPoints
            }
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getAdminStatusMessage = async (req, res) => {
    try {
        const userId = req.user._id;
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        const activeQuests = await Quest.find({ userId, status: "active" });

        const prompt = `
            You are the System Administrator from Solo Leveling. 
            Speak to the Player in your characteristic cold, intimidating, but slightly encouraging tone.
            
            Player State:
            - Level: ${user.level} (HP: ${user.hp}/${user.maxHp}, MP: ${user.mp}/${user.maxMp})
            - Stat Points Available: ${user.availableStatPoints}
            - Active Quests: ${activeQuests.length > 0 ? activeQuests.map(q => q.title).join(', ') : 'None'}
            
            Task:
            Generate a short, ONE-SENTENCE greeting/comment (max 25 words) reflecting their state.
            Priorities:
            1. If HP < 30%, warn them about their mortality.
            2. If there are active quests, command them to stop idling.
            3. If there are available stat points, tell them to stop wasting potential.
            4. Otherwise, a generic but intimidating welcome mentioning their level.
            
            Return ONLY the string message (no quotes, no extra text).
        `;

        const message = await generateAiResponse(prompt);
        res.status(200).json({ success: true, message: message.trim().replace(/^"|"$/g, '') });
    } catch (error) {
        console.error("Admin Message Error:", error);
        res.status(500).json({ message: "The System is busy analyzing your data..." });
    }
};
