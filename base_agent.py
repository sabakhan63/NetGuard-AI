"""
Base Agent Module
Defines standard finding object that inherits from dict for seamless JSON serialization.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class AgentFinding(dict):
    """
    Standardized result object that inherits from dict.
    Enables direct JSON serialization via json.dumps(output) while
    also allowing attribute-style access (e.g., output.findings, output.severity).
    """
    def __init__(
        self,
        agent: str,
        summary: str,
        severity: str = "medium",
        findings: List[str] = None,
        details: Dict[str, Any] = None,
        **kwargs
    ):
        findings = findings or []
        details = details or {}
        super().__init__(
            agent=agent,
            summary=summary,
            severity=severity,
            findings=findings,
            details=details,
            **kwargs
        )
        self.agent = agent
        self.summary = summary
        self.severity = severity
        self.findings = findings
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return dict(self)

    def render(self) -> str:
        """Render findings in human-readable academic report format."""
        lines = [f"{self.agent}:"]
        for f in self.findings:
            lines.append(f"{f}")
        return "\n".join(lines)


class BaseInvestigationAgent(ABC):
    """Abstract base class for all specialized investigation agents."""
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def analyze(self, flow_data: Any) -> AgentFinding:
        """Analyze incoming network flow data and return findings."""
        pass

    def investigate(self, flow_data: Any) -> AgentFinding:
        """Alias for analyze to ensure backwards compatibility."""
        return self.analyze(flow_data)
