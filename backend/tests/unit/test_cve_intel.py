from app.services.cve_intel import _parse_kev_vulnerability, _parse_nvd_vulnerability


def test_parse_nvd_vulnerability_extracts_cvss_cwe_cpe_and_refs():
    item = {
        "cve": {
            "id": "CVE-2026-12345",
            "published": "2026-06-01T00:00:00.000",
            "lastModified": "2026-06-02T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Remote command execution in test product."}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "baseSeverity": "CRITICAL",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 9.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                    }
                ]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
            "references": [{"url": "https://example.test/advisory", "source": "Vendor", "tags": ["Patch"]}],
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}]}]}],
        }
    }

    parsed = _parse_nvd_vulnerability(item)

    assert parsed is not None
    assert parsed.cve_id == "CVE-2026-12345"
    assert parsed.cvss_score == "9.8"
    assert parsed.cvss_severity == "CRITICAL"
    assert parsed.cwe_ids == ["CWE-78"]
    assert parsed.cpe_matches == ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
    assert parsed.references[0]["url"] == "https://example.test/advisory"


def test_parse_kev_vulnerability_marks_known_exploited():
    parsed = _parse_kev_vulnerability(
        {
            "cveID": "CVE-2026-54321",
            "vendorProject": "Example",
            "product": "VPN",
            "vulnerabilityName": "Example VPN Command Injection",
            "shortDescription": "Exploited in the wild.",
            "requiredAction": "Apply mitigations.",
            "dueDate": "2026-07-01",
            "dateAdded": "2026-06-15",
            "notes": "https://example.test/kev",
        },
        {"dateReleased": "2026-06-16"},
    )

    assert parsed is not None
    assert parsed.cve_id == "CVE-2026-54321"
    assert parsed.known_exploited is True
    assert parsed.kev_due_date == "2026-07-01"
    assert "known-exploited" in parsed.tags
