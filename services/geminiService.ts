import { GoogleGenAI } from "@google/genai";

const getClient = () => {
  const apiKey = process.env.API_KEY;
  if (!apiKey) {
    console.warn("API_KEY not found in environment");
  }
  return new GoogleGenAI({ apiKey: apiKey || 'dummy-key' });
};

export const explainPlugin = async (pluginName: string): Promise<string> => {
  const ai = getClient();
  
  const prompt = `
    You are a Senior Digital Forensics Incident Response (DFIR) expert specializing in memory forensics.
    
    Please explain the Volatility plugin named "${pluginName}".
    
    Structure your response in Markdown:
    1. **Overview**: One sentence summary of what it does.
    2. **Usage**: Why a forensic analyst uses it (e.g., detecting rootkits, finding hidden processes).
    3. **Syntax**: A hypothetical command example: \`vol.py -f image.mem --profile=Win10x64 ${pluginName}\`.
    4. **Output Analysis**: Briefly explain what the output columns usually signify.

    Keep the tone technical, "hacker-ish", and concise. Do not use conversational filler.
  `;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        thinkingConfig: { thinkingBudget: 0 } // Disable thinking for faster response
      }
    });
    
    return response.text || "NO DATA RECEIVED FROM MAINFRAME.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return `ERROR: CONNECTION TO KNOWLEDGE BASE FAILED. \n\nMANUAL OVERRIDE REQUIRED.\n\nDetails: ${(error as Error).message}`;
  }
};