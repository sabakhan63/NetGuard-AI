"""
Investigation Coordinator
Orchestrates the 3 specialized investigation agents:
1. Traffic Analysis Agent
2. Anomaly Analysis Agent
3. Attack Classification Agent
Produces individual agent findings and a synthesized multi-perspective assessment.
"""

from typing import Dict, Any, List
from .traffic_agent import TrafficAnalysisAgent
from .anomaly_agent import AnomalyAnalysisAgent
from .classification_agent import AttackClassificationAgent


class MultiAgentInvestigationCoordinator:
    """
    Coordinates multi-perspective investigations across specialized security agents.
    """
    def __init__(self, model_path: str = "intrusion_detection_model.pkl"):
        self.traffic_agent = TrafficAnalysisAgent()
        self.anomaly_agent = AnomalyAnalysisAgent()
        self.classification_agent = AttackClassificationAgent(model_path=model_path)

    def fit_baseline(self, baseline_df):
        """Fits anomaly baseline across agents."""
        self.anomaly_agent.fit_baseline(baseline_df)

    def investigate(self, flow_data: Any) -> Dict[str, Any]:
        """
        Runs all 3 specialized agents on the provided network flow data.
        Returns a dictionary containing individual findings and a composite verdict.
        """
        # Execute the 3 specialized agents
        traffic_finding = self.traffic_agent.analyze(flow_data)
        anomaly_finding = self.anomaly_agent.analyze(flow_data)
        classification_finding = self.classification_agent.analyze(flow_data)

        # Synthesize multi-perspective threat assessment
        is_attack = bool(
            classification_finding.get("is_attack", False) or
            anomaly_finding.get("anomaly_score", 0.0) >= 0.50 or
            traffic_finding.get("severity") == "high"
        )

        pred_category = classification_finding.get("predicted_attack", "Normal Traffic")
        overall_status = "MALICIOUS TRAFFIC DETECTED" if is_attack else "LEGITIMATE TRAFFIC"

        # Determine suggested mitigation
        mitigation = "No action required. Traffic is within normal operational bounds."
        if is_attack:
            if "DDoS" in pred_category or "DoS" in pred_category:
                mitigation = "Immediate rate-limiting recommended; enforce SYN flood cookies and block originating IP subnet."
            elif "Scan" in pred_category or "Probe" in pred_category:
                mitigation = "Reconnaissance detected; drop ingress packets from host and notify SOC of potential scanning."
            elif "Brute" in pred_category or "R2L" in pred_category:
                mitigation = "Authentication brute-force suspected; temporarily lock account and restrict login IP."
            else:
                mitigation = "Suspicious activity detected; isolate affected network segment and inspect payload packets."

        return {
            "status": overall_status,
            "is_attack": is_attack,
            "overall_verdict": f"{overall_status}: {pred_category}",
            "mitigation_recommendation": mitigation,
            "agents": {
                "traffic_agent": dict(traffic_finding),
                "anomaly_agent": dict(anomaly_finding),
                "classification_agent": dict(classification_finding)
            },
            "rendered_report": self._render_report([traffic_finding, anomaly_finding, classification_finding])
        }

    def _render_report(self, findings: List[Any]) -> str:
        """Renders report in human-readable format."""
        blocks = []
        for finding in findings:
            if hasattr(finding, "render"):
                blocks.append(finding.render())
            elif isinstance(finding, dict):
                lines = [f"{finding.get('agent', 'Agent')}:"]
                for f in finding.get("findings", []):
                    lines.append(f"  • {f}")
                blocks.append("\n".join(lines))
        return "\n\n".join(blocks)
