import OpenAI from "openai";
import dotenv from "dotenv";

dotenv.config();

const groq = new OpenAI({
    apiKey: process.env.GROQ_API_KEY,
    baseURL: "https://api.groq.com/openai/v1",
});

// Using a fast, high-quality model available on Groq
const DEFAULT_MODEL = "llama-3.1-8b-instant"; 

/**
 * Generates an AI response using the Groq cloud service via the OpenAI SDK.
 * This replaces the legacy Gemini implementation for higher performance.
 */
export const generateAiResponse = async (prompt, systemMessage = "") => {
    try {
        const messages = [];
        if (systemMessage) {
            messages.push({ role: "system", content: systemMessage });
        }
        messages.push({ role: "user", content: prompt });

        const completion = await groq.chat.completions.create({
            model: DEFAULT_MODEL,
            messages: messages,
            temperature: 0.7,
            max_tokens: 2048,
        });

        return completion.choices[0].message.content;
    } catch (error) {
        console.error("Groq AI Service Error:", error);
        throw error;
    }
};
