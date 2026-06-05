"""
agent_reasoning.py — LLM-powered explanation for agent decisions
=================================================================
Uses a local Ollama model (Mistral 7B) to turn raw correlation data
into a clear, human-readable rationale for a recommended action.

Design notes:
  • On-demand only — called when an admin views/approves a pending action.
  • Runs fully offline via http://localhost:11434 (no cloud, no API key).
  • Output is capped + temperature low for concise, deterministic answers.
  • Graceful fallback: if Ollama is down, returns the template reasoning.
"""

import json
import requests
from typing import Dict, Any, Optional

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "mistral:7b"
TIMEOUT_SECS = 120


SYSTEM_PROMPT = """You are a SOC (Security Operations Center) analyst assistant inside an \
intrusion detection system called CyGuardian-X. You explain why an automated agent \
recommended a security action. Be precise, factual, and concise. Use plain English a \
junior analyst can understand. Do NOT invent details not present in the data. \
Maximum 4 sentences."""


def _build_prompt(action: Dict[str, Any], correlation: Optional[Dict] = None) -> str:
    """Compose a focused prompt from the action + correlation evidence."""
    lines = [
        f"A CyGuardian-X agent recommended the action: {action.get('action_type')} "
        f"on target {action.get('target')}.",
        f"Severity: {action.get('severity')}. Confidence: {action.get('confidence')}%.",
        f"Autonomy level: {action.get('autonomy_level')}.",
    ]

    if correlation:
        sn = correlation.get("shieldnet_matches", 0)
        dd = correlation.get("deepdefend_matches", 0)
        lines.append(f"ShieldNet signature matches: {sn}. DeepDefend AI detections: {dd}.")

        engines = correlation.get("engines", {})
        sigs = engines.get("shieldnet", [])
        if sigs:
            lines.append(f"Signature rules fired: {', '.join(str(s) for s in sigs[:5])}.")
        ai = engines.get("deepdefend", [])
        if ai:
            ai_desc = ", ".join(f"{a.get('class')} ({a.get('conf')}%)" for a in ai[:3])
            lines.append(f"AI predictions: {ai_desc}.")

        if correlation.get("is_known_bad"):
            lines.append("This IP appears on a known-bad reputation list.")
        if correlation.get("reason"):
            lines.append(f"Correlation engine note: {correlation.get('reason')}")

    lines.append("\nExplain in 2-4 sentences why this action was recommended and whether "
                 "a human should approve it. Mention any risk of false positive.")
    return "\n".join(lines)


def generate_reasoning(action: Dict[str, Any],
                       correlation: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Returns {"reasoning": str, "source": "llm"|"fallback", "error": str|None}
    Never raises — always returns a usable explanation.
    """
    prompt = _build_prompt(action, correlation)

    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model":  OLLAMA_MODEL,
                "system": SYSTEM_PROMPT,
                "prompt": prompt,
                "stream": False,
                "keep_alive": "30m",   # keep model warm in RAM
                "options": {
                    "temperature": 0.3,
                    "num_predict": 200,    # cap output length for speed
                    "top_p": 0.9,
                },
            },
            timeout=TIMEOUT_SECS,
        )
        resp.raise_for_status()
        data = resp.json()
        text = (data.get("response") or "").strip()

        if not text:
            raise ValueError("empty response from model")

        return {"reasoning": text, "source": "llm", "error": None}

    except Exception as e:
        # Graceful fallback to the agent's template reasoning
        fallback = action.get("reasoning") or "No LLM reasoning available (Ollama offline)."
        return {"reasoning": fallback, "source": "fallback", "error": str(e)}


def health_check() -> Dict[str, Any]:
    """Check if Ollama is up and the model is available."""
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=5)
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        return {
            "online":          True,
            "model_available": any(OLLAMA_MODEL in m for m in models),
            "models":          models,
        }
    except Exception as e:
        return {"online": False, "model_available": False, "error": str(e)}


def warmup():
    """Preload the model into RAM so the first real call is fast."""
    try:
        requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": "ok", "stream": False,
                  "keep_alive": "30m", "options": {"num_predict": 1}},
            timeout=120,
        )
        print(f"[REASONING] Model {OLLAMA_MODEL} warmed up and loaded")
    except Exception as e:
        print(f"[REASONING] Warmup failed (will load on first use): {e}")
