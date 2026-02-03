"""
ATT&CK data synchronization service.

Fetches MITRE ATT&CK Enterprise Matrix data using the official mitreattack-python library
and caches it in the local database.
"""
import asyncio
import logging
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from mitreattack.stix20 import MitreAttackData
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.attack_technique import AttackTechnique, RuleAttackMapping

logger = logging.getLogger(__name__)

# URL to download the MITRE ATT&CK Enterprise STIX bundle
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


@dataclass
class SyncResult:
    """Result of ATT&CK sync operation."""

    success: bool
    message: str
    techniques_updated: int = 0
    new_techniques: int = 0
    error: str | None = None


class AttackSyncService:
    """Service for syncing MITRE ATT&CK data."""

    # Official MITRE tactic short names to display names
    TACTIC_DISPLAY_NAMES = {
        "reconnaissance": "Reconnaissance",
        "resource-development": "Resource Development",
        "initial-access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege-escalation": "Privilege Escalation",
        "defense-evasion": "Defense Evasion",
        "credential-access": "Credential Access",
        "discovery": "Discovery",
        "lateral-movement": "Lateral Movement",
        "collection": "Collection",
        "command-and-control": "Command and Control",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }

    def _fetch_attack_data(self) -> tuple[list[dict], dict[str, str]]:
        """
        Fetch ATT&CK data synchronously (runs in thread pool).

        Downloads the latest STIX bundle from MITRE's GitHub repository,
        saves it to a temporary file, and parses it.

        Returns tuple of (techniques, tactic_id_map).
        """
        # Download the STIX bundle from MITRE
        logger.info("Downloading ATT&CK STIX bundle from %s", ATTACK_STIX_URL)
        with httpx.Client(timeout=60.0) as client:
            response = client.get(ATTACK_STIX_URL)
            response.raise_for_status()
            stix_data = response.content

        # Save to a temporary file (mitreattack-python requires a file path)
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as f:
            f.write(stix_data)
            stix_filepath = f.name

        try:
            logger.info("Parsing ATT&CK STIX bundle from %s", stix_filepath)
            attack_data = MitreAttackData(stix_filepath)
            techniques = attack_data.get_techniques(remove_revoked_deprecated=True)

            # Build tactic ID map: maps short name (e.g., "credential-access") to tactic ID (e.g., "TA0006")
            tactic_id_map = {}
            tactics = attack_data.get_tactics()
            for tactic in tactics:
                # Tactics have x_mitre_shortname (e.g., "credential-access")
                # and external_references with external_id (e.g., "TA0006")
                short_name = getattr(tactic, "x_mitre_shortname", None)
                if not short_name:
                    continue

                external_refs = getattr(tactic, "external_references", [])
                for ref in external_refs:
                    if getattr(ref, "source_name", None) == "mitre-attack":
                        tactic_id_map[short_name] = getattr(ref, "external_id", None)
                        break

            return techniques, tactic_id_map
        finally:
            # Clean up temporary file
            Path(stix_filepath).unlink(missing_ok=True)

    async def sync(self, db: AsyncSession) -> SyncResult:
        """
        Fetch latest ATT&CK Enterprise data and update the database.

        Returns SyncResult with counts of updated/new techniques.
        """
        try:
            logger.info("Starting ATT&CK data sync")

            # Fetch data from MITRE in thread pool (synchronous HTTP call)
            techniques, tactic_id_map = await asyncio.to_thread(self._fetch_attack_data)
            logger.info("Fetched %d techniques, %d tactics from MITRE", len(techniques), len(tactic_id_map))

            techniques_count = 0

            for technique in techniques:
                # Skip if revoked or deprecated
                # STIX2 objects use direct attribute access, not .get()
                if getattr(technique, "revoked", False) or getattr(technique, "x_mitre_deprecated", False):
                    continue

                # Extract technique ID from external references
                external_refs = getattr(technique, "external_references", [])
                mitre_ref = next(
                    (ref for ref in external_refs if getattr(ref, "source_name", None) == "mitre-attack"),
                    None,
                )
                if not mitre_ref:
                    continue

                technique_id = getattr(mitre_ref, "external_id", None)
                if not technique_id:
                    continue

                # Determine if sub-technique
                is_subtechnique = "." in technique_id
                parent_id = technique_id.rsplit(".", 1)[0] if is_subtechnique else None

                # Get tactic(s) - techniques can belong to multiple tactics
                kill_chain_phases = getattr(technique, "kill_chain_phases", [])
                for phase in kill_chain_phases:
                    if getattr(phase, "kill_chain_name", None) != "mitre-attack":
                        continue

                    tactic_short_name = getattr(phase, "phase_name", None)
                    if tactic_short_name not in self.TACTIC_DISPLAY_NAMES:
                        continue

                    # Get tactic ID from the pre-built map
                    tactic_id = tactic_id_map.get(tactic_short_name)
                    if not tactic_id:
                        continue

                    # Upsert technique
                    stmt = insert(AttackTechnique).values(
                        id=technique_id,
                        name=getattr(technique, "name", ""),
                        tactic_id=tactic_id,
                        tactic_name=self.TACTIC_DISPLAY_NAMES.get(tactic_short_name, tactic_short_name),
                        parent_id=parent_id,
                        description=getattr(technique, "description", None),
                        url=getattr(mitre_ref, "url", None),
                        platforms=getattr(technique, "x_mitre_platforms", None),
                        data_sources=getattr(technique, "x_mitre_data_sources", None),
                        is_subtechnique=is_subtechnique,
                        updated_at=datetime.now(UTC),
                    ).on_conflict_do_update(
                        index_elements=["id"],
                        set_={
                            "name": getattr(technique, "name", ""),
                            "description": getattr(technique, "description", None),
                            "url": getattr(mitre_ref, "url", None),
                            "platforms": getattr(technique, "x_mitre_platforms", None),
                            "data_sources": getattr(technique, "x_mitre_data_sources", None),
                            "updated_at": datetime.now(UTC),
                        },
                    )

                    await db.execute(stmt)
                    techniques_count += 1

            await db.commit()

            # Count total techniques
            count_result = await db.execute(select(AttackTechnique))
            total_count = len(count_result.scalars().all())

            logger.info("ATT&CK sync complete: %d technique upserts, %d total in DB", techniques_count, total_count)

            return SyncResult(
                success=True,
                message="ATT&CK data synchronized successfully",
                techniques_updated=total_count,
                new_techniques=0,
            )

        except Exception as e:
            logger.error("ATT&CK sync failed: %s", e)
            await db.rollback()
            return SyncResult(
                success=False,
                message="ATT&CK sync failed",
                error=str(e),
            )

# Tag parsing for rule-to-technique mapping
TECHNIQUE_PATTERN = re.compile(r"attack\.t(\d{4})(?:\.(\d{3}))?", re.IGNORECASE)


def extract_attack_tags(tags: list[str]) -> list[str]:
    """
    Extract ATT&CK technique IDs from rule tags.

    Handles patterns like:
    - attack.t1059 -> T1059
    - attack.t1059.001 -> T1059.001

    Returns list of normalized technique IDs.
    """
    technique_ids = []

    for tag in tags:
        match = TECHNIQUE_PATTERN.match(tag)
        if match:
            main_id = f"T{match.group(1)}"
            if match.group(2):
                technique_ids.append(f"{main_id}.{match.group(2)}")
            else:
                technique_ids.append(main_id)

    return technique_ids


async def update_rule_attack_mappings(
    db: AsyncSession,
    rule_id: str,
    tags: list[str],
) -> None:
    """
    Update rule-to-technique mappings based on rule tags.

    Called on rule save/update. Deletes existing mappings and creates new ones.
    """
    from uuid import UUID

    # Convert string to UUID if needed for database operations
    rule_uuid = UUID(rule_id) if isinstance(rule_id, str) else rule_id

    # Extract technique IDs from tags
    technique_ids = extract_attack_tags(tags)

    # Delete existing mappings for this rule
    await db.execute(delete(RuleAttackMapping).where(RuleAttackMapping.rule_id == rule_uuid))

    if not technique_ids:
        return

    # Only map to techniques that exist in our database
    existing_result = await db.execute(
        select(AttackTechnique.id).where(AttackTechnique.id.in_(technique_ids))
    )
    existing_ids = {row[0] for row in existing_result}

    # Create new mappings
    for technique_id in technique_ids:
        if technique_id in existing_ids:
            mapping = RuleAttackMapping(
                rule_id=rule_uuid,
                technique_id=technique_id,
            )
            db.add(mapping)


# Singleton instance
attack_sync_service = AttackSyncService()
