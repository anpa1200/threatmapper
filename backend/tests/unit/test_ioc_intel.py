from app.services.ioc_intel import IOCImportItem, _item_technique_ids, _malpedia_family_to_import_item


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
