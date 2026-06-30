from app.services.telemetry_readiness import build_telemetry_readiness


def test_powershell_readiness_highlights_script_block_gap():
    readiness = build_telemetry_readiness(
        "T1059.001",
        "PowerShell",
        ["execution"],
        ["Windows"],
        ["Process: Process Creation", "Command: Command Execution"],
    )

    assert readiness.required_data_components == [
        "Process Creation",
        "Command Execution",
        "Script Block Logging",
        "Module Load",
    ]
    assert "Sysmon Event ID 1" in readiness.available_logs
    assert "Script Block Logging" in readiness.missing_telemetry
    assert readiness.detection_feasibility == "Medium"
    assert readiness.readiness_score <= 65
    assert any("Script Block Logging" in gap for gap in readiness.gaps)


def test_unknown_technique_gets_generic_readiness():
    readiness = build_telemetry_readiness(
        "T9999",
        "Unknown Technique",
        [],
        [],
        [],
    )

    assert readiness.required_data_components == ["Process Creation", "Network Connection"]
    assert "Sysmon Event ID 1" in readiness.available_logs
    assert readiness.detection_feasibility == "High"
    assert readiness.readiness_score == 100
