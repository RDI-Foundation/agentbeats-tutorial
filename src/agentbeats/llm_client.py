"""
Unified LLM client supporting multiple providers (OpenAI, Google Gemini).

Set LLM_PROVIDER environment variable to choose provider:
- LLM_PROVIDER=openai (requires OPENAI_API_KEY)
- LLM_PROVIDER=google (requires GOOGLE_API_KEY) [default]
"""

import os
import json
from typing import Any, Type
from pydantic import BaseModel


class LLMClient:
    """Unified client for LLM providers"""

    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "google").lower()

        if self.provider == "openai":
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            self._model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        elif self.provider == "google":
            from google import genai
            self._client = genai.Client()
            self._model = os.getenv("GOOGLE_MODEL", "gemini-2.0-flash-exp")
        else:
            raise ValueError(f"Unknown LLM_PROVIDER: {self.provider}. Use 'openai' or 'google'")

    async def generate_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_schema: Type[BaseModel]
    ) -> BaseModel:
        """
        Generate structured output matching a Pydantic schema.

        Args:
            system_prompt: System instructions
            user_prompt: User query
            response_schema: Pydantic model class for response

        Returns:
            Instance of response_schema
        """
        if self.provider == "openai":
            return await self._generate_openai(system_prompt, user_prompt, response_schema)
        else:  # google
            return await self._generate_google(system_prompt, user_prompt, response_schema)

    async def _generate_openai(
        self,
        system_prompt: str,
        user_prompt: str,
        response_schema: Type[BaseModel]
    ) -> BaseModel:
        """Generate using OpenAI with structured outputs"""
        response = await self._client.beta.chat.completions.parse(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format=response_schema
        )

        return response.choices[0].message.parsed

    async def _generate_google(
        self,
        system_prompt: str,
        user_prompt: str,
        response_schema: Type[BaseModel]
    ) -> BaseModel:
        """Generate using Google Gemini with structured outputs"""
        from google import genai

        response = await self._client.aio.models.generate_content(
            model=self._model,
            config=genai.types.GenerateContentConfig(
                system_instruction=system_prompt,
                response_mime_type="application/json",
                response_schema=response_schema,
            ),
            contents=user_prompt,
        )

        return response.parsed

    async def generate_text(
        self,
        system_prompt: str,
        user_prompt: str
    ) -> str:
        """
        Generate text output.

        Args:
            system_prompt: System instructions
            user_prompt: User query

        Returns:
            Generated text
        """
        if self.provider == "openai":
            response = await self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )
            return response.choices[0].message.content

        else:  # google
            from google import genai

            response = await self._client.aio.models.generate_content(
                model=self._model,
                config=genai.types.GenerateContentConfig(
                    system_instruction=system_prompt,
                ),
                contents=user_prompt,
            )

            return response.text
