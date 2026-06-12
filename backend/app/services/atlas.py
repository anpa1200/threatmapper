from __future__ import annotations


def normalize_atlas(payload: dict) -> dict:
    """Normalize MITRE ATLAS STIX or the public ThreatMapper web data shape."""
    if payload.get("type") == "bundle":
        techniques = [
            {
                "id": next((ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("external_id")), obj.get("id")),
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
            }
            for obj in payload.get("objects", [])
            if obj.get("type") == "attack-pattern" and not obj.get("revoked")
        ]
    else:
        techniques = [
            {"id": item.get("id"), "name": item.get("name", ""), "description": item.get("description", "")}
            for item in payload.get("techniques", [])
        ]
    return {"framework": "MITRE ATLAS", "techniques": techniques, "technique_count": len(techniques)}
