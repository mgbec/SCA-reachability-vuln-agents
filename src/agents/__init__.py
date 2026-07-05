"""Agent implementations for the reachability-enhanced SCA platform.

Exports the three core agent classes:
- OrchestratorAgent: Coordinates vulnerability analysis across sub-agents
- ScannerAgent: Accesses GitHub repositories via user-delegated OAuth
- AnalysisAgent: Performs call graph analysis, scoring, and recommendations

And the AWS Lambda/AgentCore Runtime handler:
- analysis_handler: Lambda entry point for Analysis Agent deployment

And the startup/wiring module:
- initialize_platform: Wires all agents with mTLS and identity propagation
- create_platform_from_environment: Single-call platform startup
"""

from src.agents.analysis import AnalysisAgent
from src.agents.analysis_handler import handler as analysis_handler
from src.agents.orchestrator import OrchestratorAgent
from src.agents.scanner import ScannerAgent
from src.agents.startup import create_platform_from_environment, initialize_platform

__all__ = [
    "OrchestratorAgent",
    "ScannerAgent",
    "AnalysisAgent",
    "analysis_handler",
    "initialize_platform",
    "create_platform_from_environment",
]
