"""
Agent 2: Anomaly Analysis Agent
Specialized agent comparing current network flow metrics against
a baseline of normal network behavior to compute an Anomaly Score.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Union, Optional
from sklearn.ensemble import IsolationForest
from .base_agent import BaseInvestigationAgent, AgentFinding


class AnomalyAnalysisAgent(BaseInvestigationAgent):
    """
    Anomaly Analysis Agent evaluates behavioral deviation from normal network traffic profiles.
    Supports baseline fitting via fit_baseline() or loading a pre-trained anomaly model.
    """
    def __init__(self, model_path: Optional[str] = None, threshold: float = 0.50):
        super().__init__(
            name="Anomaly Analysis Agent",
            description="Evaluates behavioral deviation from normal network traffic profiles."
        )
        self.threshold = threshold
        self.baseline_mean = None
        self.baseline_std = None
        self.iforest = None
        self.feature_names = None
        self.ready = False

        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

    def load_model(self, model_path: str):
        """Loads serialized anomaly model artifact if present."""
        try:
            artifact = joblib.load(model_path)
            self.iforest = artifact.get("iforest")
            self.baseline_mean = artifact.get("mean")
            self.baseline_std = artifact.get("std")
            self.feature_names = artifact.get("feature_names")
            self.ready = True
        except Exception:
            self.ready = False

    def fit_baseline(self, baseline_df: pd.DataFrame):
        """
        Fits baseline statistics and Isolation Forest on normal baseline traffic.
        Example: anomaly_agent.fit_baseline(X_test.iloc[:500])
        """
        if isinstance(baseline_df, pd.Series):
            baseline_df = baseline_df.to_frame().T

        numeric_df = baseline_df.select_dtypes(include=[np.number]).fillna(0)
        self.feature_names = list(numeric_df.columns)
        self.baseline_mean = numeric_df.mean(axis=0).values
        self.baseline_std = np.maximum(numeric_df.std(axis=0).fillna(0).values, 0.05)

        # Fit Isolation Forest on baseline
        self.iforest = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42,
            n_jobs=-1
        )
        self.iforest.fit(numeric_df)
        self.ready = True

    def analyze(self, flow_data: Union[pd.Series, pd.DataFrame, Dict[str, Any]]) -> AgentFinding:
        """Computes Anomaly Score and identifies features deviating from normal baseline."""
        if isinstance(flow_data, pd.DataFrame):
            df_row = flow_data.iloc[[0]]
        elif isinstance(flow_data, pd.Series):
            df_row = flow_data.to_frame().T
        else:
            df_row = pd.DataFrame([flow_data])

        findings: List[str] = []
        metrics: Dict[str, Any] = {}

        if self.ready and self.baseline_mean is not None:
            # Align features
            aligned = df_row.reindex(columns=self.feature_names, fill_value=0.0).fillna(0.0)
            x_vals = aligned.values[0]

            # 1. Z-score deviation relative to baseline
            z_scores = np.abs((x_vals - self.baseline_mean) / self.baseline_std)
            max_z = float(np.max(z_scores)) if len(z_scores) > 0 else 0.0
            avg_z = float(np.mean(z_scores)) if len(z_scores) > 0 else 0.0

            # 2. Isolation Forest score
            raw_iforest = -float(self.iforest.score_samples(aligned)[0])

            # Normalized Anomaly Score in [0.0, 1.0]
            # Baseline samples have max_z ~= 1-2, attacks have max_z > 3
            z_norm = min(1.0, max(0.05, max_z / 4.0))
            if_norm = min(1.0, max(0.05, (raw_iforest - 0.4) / 0.4)) if raw_iforest > 0.4 else 0.1
            anomaly_score = round(max(z_norm, if_norm), 2)
            # Bound within [0.05, 0.99]
            anomaly_score = max(0.05, min(0.99, anomaly_score))

            metrics["max_z_score"] = round(max_z, 2)
            metrics["avg_z_score"] = round(avg_z, 2)
            metrics["iforest_raw"] = round(raw_iforest, 4)
        else:
            # Fallback heuristic calculation if fit_baseline was not called
            row_s = df_row.iloc[0]
            def _get(k, d=0.0):
                val = row_s.get(k, d)
                try:
                    return d if pd.isna(val) else float(val)
                except Exception:
                    return d
            rerror = _get("rerror_rate", _get("23", 0.0))
            serror = _get("serror_rate", _get("21", 0.0))
            count = _get("count", _get("19", 1.0))

            score = 0.10
            if abs(rerror) > 1.0 or abs(serror) > 1.0:
                score += 0.50
            if abs(count) > 1.0:
                score += 0.25
            anomaly_score = round(min(0.99, max(0.05, score)), 2)

        metrics["anomaly_score"] = anomaly_score
        is_anomalous = anomaly_score >= self.threshold

        if is_anomalous:
            findings.append("Traffic deviates significantly from normal behaviour.")
            findings.append(f"Anomaly score: {anomaly_score:.2f}")
            if metrics.get("max_z_score", 0) > 2.0:
                findings.append(f"Statistical divergence: peak feature variation {metrics['max_z_score']:.1f} std-devs from baseline")
            severity = "high" if anomaly_score >= 0.75 else "medium"
        else:
            findings.append("Traffic conforms to expected baseline behavior.")
            findings.append(f"Anomaly score: {anomaly_score:.2f}")
            severity = "low"

        return AgentFinding(
            agent=self.name,
            summary=f"Anomaly score: {anomaly_score:.2f}",
            severity=severity,
            findings=findings,
            details=metrics,
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous
        )

    def investigate(self, flow_data: Any) -> AgentFinding:
        return self.analyze(flow_data)
