"""
Agent 1: Traffic Analysis Agent
Specialized agent analyzing low-level traffic characteristics:
- Packet/flow statistics
- Duration
- Protocol
- Source/destination information
- Traffic volume
"""

import pandas as pd
import numpy as np
from typing import Dict, Any, List, Union
from .base_agent import BaseInvestigationAgent, AgentFinding


class TrafficAnalysisAgent(BaseInvestigationAgent):
    """
    Traffic Analysis Agent evaluates raw flow properties, protocol states,
    and volume dynamics to spot network-layer aberrations.
    """
    def __init__(self):
        super().__init__(
            name="Traffic Analysis Agent",
            description="Analyzes flow statistics, packet metrics, protocol behavior, and traffic volume."
        )

    def _extract_metric(self, row: Any, key: str, idx: int, default: float = 0.0) -> float:
        """Extracts metric safely whether indexed by feature name or numerical column index."""
        try:
            if isinstance(row, pd.DataFrame):
                row = row.iloc[0]
            if hasattr(row, "get"):
                if key in row:
                    v = row.get(key, default)
                    return default if pd.isna(v) else float(v)
                str_idx = str(idx)
                if str_idx in row:
                    v = row.get(str_idx, default)
                    return default if pd.isna(v) else float(v)
            if hasattr(row, "__getitem__"):
                v = row[idx] if len(row) > idx else default
                return default if pd.isna(v) else float(v)
        except Exception:
            pass
        return default

    def analyze(self, flow_data: Union[pd.Series, pd.DataFrame, Dict[str, Any]]) -> AgentFinding:
        """Analyze flow data and return structured findings."""
        if isinstance(flow_data, pd.DataFrame):
            row = flow_data.iloc[0]
        else:
            row = flow_data

        findings: List[str] = []
        metrics: Dict[str, Any] = {}
        risk_score = 0.0

        # Extract metrics (supporting both named and standardized/indexed columns)
        duration = self._extract_metric(row, "duration", 0, 0.0)
        src_bytes = self._extract_metric(row, "src_bytes", 1, 0.0)
        dst_bytes = self._extract_metric(row, "dst_bytes", 2, 0.0)
        count = self._extract_metric(row, "count", 19, 1.0)
        srv_count = self._extract_metric(row, "srv_count", 20, 1.0)
        serror_rate = self._extract_metric(row, "serror_rate", 21, 0.0)
        rerror_rate = self._extract_metric(row, "rerror_rate", 23, 0.0)
        diff_srv_rate = self._extract_metric(row, "diff_srv_rate", 26, 0.0)
        dst_host_count = self._extract_metric(row, "dst_host_count", 28, 1.0)

        # Byte ratio
        byte_ratio = self._extract_metric(row, "byte_ratio", -1, 0.0)
        if byte_ratio == 0.0:
            byte_ratio = src_bytes / (dst_bytes + 1.0) if dst_bytes >= 0 else src_bytes

        metrics["duration"] = round(duration, 4)
        metrics["src_bytes"] = round(src_bytes, 4)
        metrics["dst_bytes"] = round(dst_bytes, 4)
        metrics["byte_ratio"] = round(byte_ratio, 4)
        metrics["connection_count"] = round(count, 4)

        # 1. Traffic Volume & Ratio Analysis
        if src_bytes > 20000 or (src_bytes > 0.5 and dst_bytes <= 0):
            findings.append("High traffic volume detected (disproportionate source volume)")
            risk_score += 0.35
        elif abs(byte_ratio) > 50:
            findings.append("Severe flow asymmetry detected (abnormal byte ratio)")
            risk_score += 0.25

        # 2. Flow Duration Analysis
        if duration <= 0.01 or (duration < -0.10 and count > 0):
            findings.append("Unusual flow duration (instantaneous micro-burst indicative of automated attack)")
            risk_score += 0.25
        elif duration > 600:
            findings.append(f"Unusual flow duration ({duration:.0f}s persistent open connection)")
            risk_score += 0.20

        # 3. Protocol & TCP Activity Analysis
        flag = str(row.get("flag", "")).upper() if hasattr(row, "get") else ""
        if rerror_rate > 1.5 or rerror_rate > 0.5:
            findings.append(f"Suspicious TCP activity (high connection rejection rate: {rerror_rate:.2f} std-devs)")
            risk_score += 0.35
        elif serror_rate > 1.5 or serror_rate > 0.5 or flag == "S0":
            findings.append("Suspicious TCP activity (SYN flood / incomplete handshake pattern)")
            risk_score += 0.35

        # 4. Connection Counts & Burst Rates
        if count > 1.0 or count > 80:
            findings.append(f"High connection burst ({count:.1f} connection density in recent window)")
            risk_score += 0.30

        if diff_srv_rate > 1.0 or diff_srv_rate > 0.5:
            findings.append("Connections dispersed across multiple distinct services (scan-like)")
            risk_score += 0.25

        # Fallback if traffic looks standard
        if not findings:
            findings.append("Normal traffic volume and standard flow duration observed")
            findings.append("Standard protocol handshake and response rates detected")
            severity = "low"
            summary = "Traffic characteristics look ordinary"
        else:
            severity = "high" if risk_score >= 0.50 else "medium"
            summary = f"{len(findings)} suspicious traffic indicator(s) found"

        return AgentFinding(
            agent=self.name,
            summary=summary,
            severity=severity,
            findings=findings,
            details=metrics
        )

    def investigate(self, flow_data: Any) -> AgentFinding:
        return self.analyze(flow_data)
