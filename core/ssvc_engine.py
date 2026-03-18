"""
SSVC (Stakeholder-Specific Vulnerability Categorization) engine.

Based on CISA's SSVC decision tree for prioritizing vulnerability remediation.
https://www.cisa.gov/ssvc

Decision tree:
  1. Exploitation status  → Active | PoC | None
  2. Automatable          → Yes | No   (network-reachable + no user interaction)
  3. Technical Impact     → Total | Partial

Decision outcomes (highest to lowest priority):
  Immediate → Active exploitation + significant impact
  Act       → Confirmed threat signals, needs fast action
  Attend    → Relevant threat signals, prioritize in next cycle
  Track     → Low threat signals, monitor regularly
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# EPSS threshold above which we classify exploitation status as "PoC"
# 10% probability of exploitation in next 30 days indicates likely public tooling.
EPSS_POC_THRESHOLD = 0.10

# SSVC decision string constants
DECISION_IMMEDIATE = "Immediate"
DECISION_ACT = "Act"
DECISION_ATTEND = "Attend"
DECISION_TRACK = "Track"

# Normalized weights for risk scoring (0-1)
SSVC_WEIGHTS = {
    DECISION_IMMEDIATE: 1.0,
    DECISION_ACT: 0.75,
    DECISION_ATTEND: 0.50,
    DECISION_TRACK: 0.0,
}


class SSVCEngine:
    """
    Computes SSVC decision for each finding and annotates it.
    Designed to run after KEV matching and EPSS enrichment.
    """

    def score(self, finding) -> None:
        """Compute and set ssvc_decision, ssvc_exploitation, has_public_exploit on finding."""
        exploitation = self._exploitation_status(finding)
        automatable = self._automatable(finding)
        technical_impact = self._technical_impact(finding)
        decision = self._decision(exploitation, automatable, technical_impact)

        finding.ssvc_exploitation = exploitation
        finding.ssvc_decision = decision
        # A finding has a "public exploit" if there's confirmed or probable public tooling
        finding.has_public_exploit = exploitation in ("PoC", "Active")

    def score_all(self, findings: list) -> list:
        for f in findings:
            self.score(f)
        return findings

    @staticmethod
    def _exploitation_status(finding) -> str:
        """
        Active  → confirmed in CISA KEV (actively exploited in the wild)
        PoC     → EPSS score above threshold (likely public proof-of-concept)
        None    → no known exploitation evidence
        """
        if finding.in_kev:
            return "Active"
        epss = finding.epss_score or 0.0
        if epss >= EPSS_POC_THRESHOLD:
            return "PoC"
        return "None"

    @staticmethod
    def _automatable(finding) -> bool:
        """
        A vulnerability is automatable if it can be exploited over the network
        without user interaction — i.e., attack vector is Network (AV:N) or
        Adjacent (AV:A) and requires no user interaction (UI:N from CVSS vector).
        Falls back to attack_vector field if CVSS vector string unavailable.
        """
        cvss_vector = finding.cvss_vector or ""
        av = "N"  # default assumption: network accessible
        ui = "N"  # default assumption: no user interaction required

        if cvss_vector:
            for part in cvss_vector.split("/"):
                if part.startswith("AV:"):
                    av = part.split(":")[1]
                elif part.startswith("UI:"):
                    ui = part.split(":")[1]
        elif finding.attack_vector:
            av = finding.attack_vector

        return av in ("N", "A") and ui == "N"

    @staticmethod
    def _technical_impact(finding) -> str:
        """
        Total   → High impact on ALL of Confidentiality, Integrity, Availability
        Partial → Partial impact on one or more CIA components

        Derived from CVSS vector (C:H/I:H/A:H = Total) or CVSS score >= 9.0.
        """
        cvss_vector = finding.cvss_vector or ""
        cvss_score = finding.cvss_score or 0.0

        if cvss_vector:
            c = i = a = "L"
            for part in cvss_vector.split("/"):
                if part.startswith("C:"):
                    c = part.split(":")[1]
                elif part.startswith("I:"):
                    i = part.split(":")[1]
                elif part.startswith("A:"):
                    a = part.split(":")[1]
            if c == "H" and i == "H" and a == "H":
                return "Total"
            return "Partial"

        # Fallback: use CVSS score as proxy
        return "Total" if cvss_score >= 9.0 else "Partial"

    @staticmethod
    def _decision(exploitation: str, automatable: bool, technical_impact: str) -> str:
        """
        SSVC decision tree (simplified for practitioner use):

        Immediate:  Active exploitation + Automatable + Total impact
        Act:        Active exploitation (any) OR PoC + Automatable + Total
        Attend:     PoC (any) OR Automatable + High impact OR Active non-automatable
        Track:      No known exploitation, not automatable
        """
        if exploitation == "Active":
            if automatable and technical_impact == "Total":
                return DECISION_IMMEDIATE
            return DECISION_ACT

        if exploitation == "PoC":
            if automatable and technical_impact == "Total":
                return DECISION_ACT
            return DECISION_ATTEND

        # exploitation == "None"
        if automatable and technical_impact == "Total":
            return DECISION_ATTEND

        return DECISION_TRACK


def ssvc_to_norm(decision: Optional[str]) -> float:
    """Return 0-1 normalized value for use in risk scoring formula."""
    return SSVC_WEIGHTS.get(decision or DECISION_TRACK, 0.0)
