"""Regression test for config backup/restore version compatibility."""


def test_current_export_version_is_importable():
    """A backup written by the current build must be accepted by import_config.

    Previously CONFIG_SCHEMA_VERSION was bumped to "3.0" while the import gate
    still only accepted {"1.0", "2.0"}, so every fresh backup failed to restore.
    This pins the invariant that the export version is always importable.
    """
    from app.api.export import CONFIG_SCHEMA_VERSION, SUPPORTED_CONFIG_VERSIONS

    assert CONFIG_SCHEMA_VERSION in SUPPORTED_CONFIG_VERSIONS
