"""
NIST CSF and CIS Controls mapping.
Called by the RiskEngine — kept separate for easy extension.
"""

# Map finding types to NIST CSF subcategories
NIST_CSF: dict[str, list[str]] = {
    "network": ["ID.AM-1", "PR.IP-12", "DE.CM-8", "RS.MI-3"],
    "application": ["PR.IP-2", "DE.CM-4", "RS.MI-3"],
    "code": ["PR.IP-2", "DE.CM-4"],
    "configuration": ["PR.IP-1", "PR.IP-3", "DE.CM-7"],
}

# Map finding types to CIS Controls v8
CIS_CONTROLS: dict[str, list[str]] = {
    "network": ["CIS-7", "CIS-12"],
    "application": ["CIS-7", "CIS-16"],
    "code": ["CIS-16"],
    "configuration": ["CIS-4", "CIS-7"],
}

# Human-readable descriptions for reporting
NIST_CSF_DESCRIPTIONS: dict[str, str] = {
    "ID.AM-1": "Physical devices and systems within the organization are inventoried",
    "PR.IP-1": "A baseline configuration of information technology is created and maintained",
    "PR.IP-2": "A System Development Life Cycle to manage systems is implemented",
    "PR.IP-3": "Configuration change control processes are in place",
    "PR.IP-12": "A vulnerability management plan is developed and implemented",
    "DE.CM-4": "Malicious code is detected",
    "DE.CM-7": "Monitoring for unauthorized personnel, connections, devices, and software is performed",
    "DE.CM-8": "Vulnerability scans are performed",
    "RS.MI-3": "Newly identified vulnerabilities are mitigated or documented as accepted risks",
}

CIS_DESCRIPTIONS: dict[str, str] = {
    "CIS-4": "Secure Configuration of Enterprise Assets and Software",
    "CIS-7": "Continuous Vulnerability Management",
    "CIS-12": "Network Infrastructure Management",
    "CIS-16": "Application Software Security",
}


def get_nist_controls(finding_type: str) -> list[str]:
    return NIST_CSF.get(finding_type, [])


def get_cis_controls(finding_type: str) -> list[str]:
    return CIS_CONTROLS.get(finding_type, [])


def describe_nist_control(control_id: str) -> str:
    return NIST_CSF_DESCRIPTIONS.get(control_id, control_id)


def describe_cis_control(control_id: str) -> str:
    return CIS_DESCRIPTIONS.get(control_id, control_id)
