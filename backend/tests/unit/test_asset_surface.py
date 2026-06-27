from app.services.asset_surface import build_baseline_matrix, parse_inventory


def test_parse_csv_inventory_and_score_internet_assets():
    content = b"""name,type,environment,owner,ip,domain,ports,technologies,exposure,criticality
customer-portal,web-app,prod,Digital,203.0.113.10,portal.example.com,"80,443,8443","nginx,nodejs",internet,critical
ad-dc-01,identity,prod,IT,10.10.1.10,ad01.corp.local,"53,88,389,445","active-directory",internal,critical
"""

    records, _ = parse_inventory(content, "assets.csv")
    matrix = build_baseline_matrix(records)

    assert len(records) == 2
    assert matrix["exposure_counts"]["internet"] == 1
    assert matrix["assets"][0]["risk_level"] in {"high", "critical"}
    assert any(ttp["attack_id"] == "T1190" for ttp in matrix["assets"][0]["ttp_candidates"])


def test_parse_plain_text_inventory():
    records, _ = parse_inventory(b"vpn.example.com 198.51.100.20 ports 443 3389 public vpn", "assets.txt")
    matrix = build_baseline_matrix(records)

    assert records[0].domains == ["vpn.example.com"]
    assert records[0].exposure == "internet"
    assert records[0].ports == [443, 3389]
    assert 3389 in records[0].ports
    assert any(ttp["attack_id"] == "T1021" for ttp in matrix["assets"][0]["ttp_candidates"])
    assert any(ttp["attack_id"] == "T1133" for ttp in matrix["assets"][0]["ttp_candidates"])


def test_attack_surface_matrix_includes_detection_and_validation_guidance():
    content = b"""name,type,environment,owner,ip,domain,ports,technologies,exposure,criticality,tags
ci-runner,ci-cd,prod,Platform,10.4.5.6,ci.corp.local,"22,443","gitlab,runner,legacy",internal,high,"pipeline"
"""

    records, _ = parse_inventory(content, "assets.csv")
    matrix = build_baseline_matrix(records)
    row = matrix["assets"][0]

    assert any(ttp["attack_id"] == "T1195" for ttp in row["ttp_candidates"])
    assert any(ttp["attack_id"] == "T1068" for ttp in row["ttp_candidates"])
    assert row["control_gaps"]
    assert row["validation_steps"]
    assert row["detection_ideas"]
