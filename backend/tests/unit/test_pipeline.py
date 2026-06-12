from app.services.atlas import normalize_atlas
from app.services.collection import extract_observables, misp_reports, stix_reports
from app.services.detections import generate_detection, validate_detection


def test_extract_observables_deduplicates_and_validates_ipv4():
    values = extract_observables("CVE-2025-12345 at 8.8.8.8, 8.8.8.8, not 999.1.1.1")
    assert {(item["type"], item["normalized_value"]) for item in values} == {
        ("cve", "cve-2025-12345"), ("ipv4", "8.8.8.8")
    }


def test_structured_import_normalizers():
    assert stix_reports({"objects": [{"type": "report", "name": "Test"}]})[0]["title"] == "Test"
    assert misp_reports({"Event": {"info": "MISP", "Attribute": [{"type": "domain", "value": "example.org"}]}})[0]["indicators"]
    assert normalize_atlas({"techniques": [{"id": "AML.T0001", "name": "Test"}]})["technique_count"] == 1


def test_detection_skeleton_is_valid_but_warns_about_placeholder():
    rule = generate_detection("PowerShell behavior", "T1059.001", "sigma", ["process_creation"])
    result = validate_detection("sigma", rule)
    assert result["valid"] is True
    assert result["warnings"]
