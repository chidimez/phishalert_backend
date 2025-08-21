# services/llm_client.py
from abc import ABC, abstractmethod
from typing import Optional
from core.config import LLM_MODE, OPENAI_API_KEY, OPENAI_MODEL, LOCAL_LLM_BACKEND, LOCAL_LLM_MODEL

class LLMClient(ABC):
    @abstractmethod
    def generate(self, system: str, prompt: str) -> str:
        ...

class OpenAIClient(LLMClient):
    def __init__(self, api_key: str, model: str):
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def generate(self, system: str, prompt: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": prompt}]
            #temperature=0.2
        )
        return resp.choices[0].message.content

class OllamaClient(LLMClient):
    """Local via Ollama server (pip install ollama; run `ollama run <model>`)"""
    def __init__(self, model: str):
        import requests
        self.model = model
        self.url = "http://127.0.0.1:11434/api/generate"
        self.requests = requests

    def generate(self, system: str, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": f"[SYSTEM]\n{system}\n\n[USER]\n{prompt}",
            "stream": False
        }
        r = self.requests.post(self.url, json=payload, timeout=120)
        r.raise_for_status()
        data = r.json()
        return data.get("response", "")

class LlamaCppClient(LLMClient):
    """Local via llama-cpp-python (pip install llama-cpp-python)"""
    def __init__(self, model_path: str):
        from llama_cpp import Llama
        self.llm = Llama(model_path=model_path, n_ctx=8192, logits_all=False)

    def generate(self, system: str, prompt: str) -> str:
        full_prompt = f"System:\n{system}\n\nUser:\n{prompt}"
        out = self.llm(full_prompt, max_tokens=768, temperature=0.2, stop=["</json>"])
        return out["choices"][0]["text"]

def get_llm() -> LLMClient:
    if LLM_MODE == "openai":
        return OpenAIClient(api_key=OPENAI_API_KEY, model=OPENAI_MODEL)
    if LLM_MODE == "local":
        if LOCAL_LLM_BACKEND == "ollama":
            return OllamaClient(model=LOCAL_LLM_MODEL)
        else:
            # For llama_cpp, set LOCAL_LLM_MODEL to an absolute GGUF path
            return LlamaCppClient(model_path=LOCAL_LLM_MODEL)
    raise RuntimeError("Unsupported LLM_MODE")
