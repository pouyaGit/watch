from openai import OpenAI

from ai.config import OPENROUTER_API_KEY, OPENROUTER_MODEL
from ai.llm.base import LLMProvider


class OpenRouterProvider(LLMProvider):

    def __init__(self):
        if not OPENROUTER_API_KEY:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not configured"
            )

        if not OPENROUTER_MODEL:
            raise RuntimeError(
                "OPENROUTER_MODEL is not configured"
            )

        self.client = OpenAI(
            api_key=OPENROUTER_API_KEY,
            base_url="https://openrouter.ai/api/v1",
        )

    def generate(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=OPENROUTER_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )

        return response.choices[0].message.content or ""