@classmethod
def get_technology_folder(
    cls, rule_name: str, rules_dir: pathlib.Path = RULES_DIR
) -> pathlib.Path:
    """Return the technology subfolder for a rule based on its name prefix.

    Supports both flat and nested folder structures:
      - "gcp_suspicious_activity"      -> detection-rules/GCP/
      - "okta_brute_force"             -> detection-rules/Okta/
      - "cloud_gcp_test_rule"          -> detection-rules/Cloud/GCP/
      - "cloud_aws_something"          -> detection-rules/Cloud/AWS/
      - "unknown_rule"                 -> detection-rules/Other/

    To add a new flat technology:    add "prefix": "FolderName" to the map.
    To add a new nested technology:  add "prefix": {"sub": "FolderName"} to the map.
    """
    parts = rule_name.split("_")
    mapping = TECHNOLOGY_PREFIX_MAP

    folder_path = rules_dir

    for part in parts:
        match = mapping.get(part.lower())

        if match is None:
            # No match found — fall back to Other/
            folder_path = rules_dir / "Other"
            break

        if isinstance(match, str):
            # Leaf node — this is the final folder segment
            folder_path = folder_path / match
            break

        if isinstance(match, dict):
            # Intermediate node — append the key's display name and go deeper
            folder_path = folder_path / part.capitalize()
            mapping = match

    folder_path.mkdir(parents=True, exist_ok=True)
    return folder_path
