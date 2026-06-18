from app.services.virustotal import _actor_context, _extract_ttp_evidence, _match_actor_terms


def test_extract_ttp_evidence_from_nested_vt_context():
    attributes = {
        "tags": ["attack.t1059.001"],
        "crowdsourced_yara_results": [
            {"rule_name": "loader", "description": "Observed MITRE technique T1105 during execution."}
        ],
    }
    rows = _extract_ttp_evidence(attributes, "object attributes")
    attack_ids = {row["attack_id"] for row in rows}

    assert "T1059.001" in attack_ids
    assert "T1105" in attack_ids


def test_actor_match_uses_aliases_and_separator_variants():
    attributes = {
        "popular_threat_classification": {"suggested_threat_label": "APT-28 loader"},
        "crowdsourced_yara_results": [{"rule_name": "Fancy Bear credential theft"}],
    }
    context = _actor_context(attributes, {})
    matched, evidence = _match_actor_terms(["APT28", "Fancy Bear"], context)

    assert matched == ["APT28", "Fancy Bear"]
    assert {row["term"] for row in evidence} == {"APT28", "Fancy Bear"}
