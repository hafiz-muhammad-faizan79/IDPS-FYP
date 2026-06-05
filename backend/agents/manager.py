"""
manager.py — Boots, monitors, and shuts down all agents.
========================================================
Single entry-point invoked from main.py at startup:

    from agents.manager import start_all_agents, stop_all_agents
    start_all_agents()   # on FastAPI startup hook
    stop_all_agents()    # on FastAPI shutdown hook

Adding a new agent = import + register here. That's it.
"""

import threading
from typing import Dict, List
from agents.base import BaseAgent

# ─── Registry: instantiated singletons ────────────────────────
_agents: Dict[str, BaseAgent] = {}
_lock = threading.Lock()


def register(agent: BaseAgent):
    """Add an agent to the registry without starting it."""
    with _lock:
        if agent.agent_name in _agents:
            print(f"[AGENT-MGR] ⚠ agent '{agent.agent_name}' already registered")
            return
        _agents[agent.agent_name] = agent
        print(f"[AGENT-MGR] registered: {agent.agent_name}")


def start_all_agents():
    """Instantiate and start every known agent."""
    # Lazy import to avoid circular dependencies on startup
    from agents.monitor_agent  import MonitorAgent
    from agents.triage_agent   import TriageAgent
    from agents.response_agent import ResponseAgent

    # Register core 3 agents (Phase 1 scope)
    if not _agents:
        register(MonitorAgent())
        register(TriageAgent())
        register(ResponseAgent())

    for name, agent in _agents.items():
        if not agent.is_running():
            agent.start()
    print(f"[AGENT-MGR] ✅ Started {len([a for a in _agents.values() if a.is_running()])} agents")


def stop_all_agents():
    """Gracefully stop every running agent."""
    for name, agent in _agents.items():
        if agent.is_running():
            agent.stop()
    print(f"[AGENT-MGR] ⏹ Stopped all agents")


def get_all_status() -> List[Dict]:
    """Snapshot of every agent for the /api/agents endpoint."""
    return [a.status() for a in _agents.values()]


def get_agent(name: str) -> BaseAgent:
    return _agents.get(name)
