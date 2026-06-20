from app.services.ioc_investigation import _dedupe_actors, _urlscan_heuristic_analysis


def test_dedupe_actors_uses_string_key_not_tuple_lower():
    actors = [
        {"attack_id": "G0006", "name": "APT1", "source": "local"},
        {"attack_id": "G0006", "name": "APT1", "source": "other"},
        {"attack_id": "G0049", "name": "OilRig", "source": "local"},
    ]

    deduped = _dedupe_actors(actors)

    assert [item["attack_id"] for item in deduped] == ["G0006", "G0049"]


def test_urlscan_heuristic_analysis_extracts_suspicious_patterns():
    result = _urlscan_heuristic_analysis(
        "http://example.test/login",
        [
            {
                "page": {"url": "http://redirect.example/payload", "domain": "redirect.example", "ip": "203.0.113.10"},
                "task": {"url": "http://example.test/login"},
                "verdicts": {"overall": {"malicious": True}},
                "stats": {"uniqIPs": 6},
            }
        ],
        {},
    )

    patterns = {item["pattern"] for item in result["findings"]}

    assert result["mode"] == "heuristic"
    assert "malicious urlscan verdict" in patterns
    assert "multiple network destinations" in patterns
    assert "redirect or hosted-content pivot" in patterns
    assert {"T1189", "T1204"}.issubset(set(result["technique_ids"]))
