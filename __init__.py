"""
Specialized Investigation Agents Package
Contains the 3 specialized agents and coordinator for Intrusion Detection.
"""

from .base_agent import BaseInvestigationAgent, AgentFinding
from .traffic_agent import TrafficAnalysisAgent
from .anomaly_agent import AnomalyAnalysisAgent
from .classification_agent import AttackClassificationAgent
from .coordinator import MultiAgentInvestigationCoordinator

__all__ = [
    "BaseInvestigationAgent",
    "AgentFinding",
    "TrafficAnalysisAgent",
    "AnomalyAnalysisAgent",
    "AttackClassificationAgent",
    "MultiAgentInvestigationCoordinator"
]
