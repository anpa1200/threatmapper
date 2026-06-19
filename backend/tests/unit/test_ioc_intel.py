from app.services.ioc_intel import (
    IOCImportItem,
    _item_technique_ids,
    _malpedia_family_to_import_item,
    _mapping_evidence_from_item,
    _normalize_ioc_type,
)


def test_malpedia_family_to_import_item_maps_attribution_and_context():
    item = _malpedia_family_to_import_item(
        "win.example",
        {
            "common_name": "ExampleRat",
            "alt_names": ["Example RAT", "ExampleTool"],
            "attribution": ["APT28", "Fancy Bear"],
            "urls": ["https://example.test/report"],
            "sources": ["vendor report"],
            "updated": "2026-06-01",
            "uuid": "abc",
        },
    )

    assert item.value == "win.example"
    assert item.indicator_type == "malware-family"
    assert item.malware_family == "ExampleRat"
    assert item.actor_name == "APT28, Fancy Bear"
    assert item.source_url == "https://example.test/report"
    assert "Example RAT" in item.tags
    assert "APT28" in item.tags


def test_ioc_item_technique_ids_extracts_explicit_and_raw_attack_ids():
    item = IOCImportItem(
        value="203.0.113.10",
        indicator_type="ipv4",
        technique_ids=["T1105"],
        tags=["command-and-control", "T1071.001"],
        description="Observed alongside PowerShell T1059.001.",
        raw={"mitre": [{"technique_id": "T1566"}]},
    )

    assert _item_technique_ids(item) == ["T1059.001", "T1071.001", "T1105", "T1566"]


def test_ioc_type_normalization_handles_provider_hash_names():
    assert _normalize_ioc_type("sha256_hash", "a" * 64) == "sha256"
    assert _normalize_ioc_type("sha1_hash", "a" * 40) == "sha1"
    assert _normalize_ioc_type("md5_hash", "a" * 32) == "md5"


def test_ioc_ttp_mapping_evidence_preserves_priority():
    item = IOCImportItem(
        value="d41d8cd98f00b204e9800998ecf8427e",
        indicator_type="md5_hash",
        technique_ids=["T1105"],
        tags=["T1059"],
        raw={"platform_tag": "T1566"},
    )

    evidence = _mapping_evidence_from_item(item)
    by_id = {row["attack_id"]: row["priority"] for row in evidence}

    assert by_id["T1105"] == "strict-report"
    assert by_id["T1059"] == "enrichment-platform"
    assert by_id["T1566"] == "enrichment-platform"
