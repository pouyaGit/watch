from openai import OpenAI

from ai.config import AVALAI_API_KEY, AVALAI_MODEL
from ai.llm.base import LLMProvider


class AvalAIProvider(LLMProvider):

    def __init__(self):
        if not AVALAI_API_KEY:
            raise RuntimeError(
                "AVALAI_API_KEY is not configured"
            )

        if not AVALAI_MODEL:
            raise RuntimeError(
                "AVALAI_MODEL is not configured"
            )

        self.client = OpenAI(
            api_key=AVALAI_API_KEY,
            base_url="https://api.avalai.ir/v1",
        )

    def generate(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=AVALAI_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )

        return response.choices[0].message.content or ""