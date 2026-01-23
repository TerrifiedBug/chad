"""
ATT&CK data synchronization service.

Fetches MITRE ATT&CK Enterprise Matrix data using the official mitreattack-python library
and caches it in the local database.
"""
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from mitreattack.stix20 import MitreAttackData
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.attack_technique import AttackTechnique, RuleAttackMapping

logger = logging.getLogger(__name__)


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

    async def sync(self, db: AsyncSession) -> SyncResult:
        """
        Fetch latest ATT&CK Enterprise data and update the database.

        Returns SyncResult with counts of updated/new techniques.
        """
        try:
            logger.info("Starting ATT&CK data sync")

            # Fetch data from MITRE (downloads STIX bundle)
            attack_data = MitreAttackData("enterprise-attack")

            techniques_count = 0

            # Get all techniques and their relationships
            techniques = attack_data.get_techniques(remove_revoked_deprecated=True)

            for technique in techniques:
                # Skip if revoked or deprecated
                if technique.get("revoked") or technique.get("x_mitre_deprecated"):
                    continue

                # Extract technique ID from external references
                external_refs = technique.get("external_references", [])
                mitre_ref = next(
                    (ref for ref in external_refs if ref.get("source_name") == "mitre-attack"),
                    None,
                )
                if not mitre_ref:
                    continue

                technique_id = mitre_ref.get("external_id")
                if not technique_id:
                    continue

                # Determine if sub-technique
                is_subtechnique = "." in technique_id
                parent_id = technique_id.rsplit(".", 1)[0] if is_subtechnique else None

                # Get tactic(s) - techniques can belong to multiple tactics
                kill_chain_phases = technique.get("kill_chain_phases", [])
                for phase in kill_chain_phases:
                    if phase.get("kill_chain_name") != "mitre-attack":
                        continue

                    tactic_short_name = phase.get("phase_name")
                    if tactic_short_name not in self.TACTIC_DISPLAY_NAMES:
                        continue

                    # Get tactic ID from the tactic object
                    tactic_id = self._get_tactic_id(attack_data, tactic_short_name)
                    if not tactic_id:
                        continue

                    # Upsert technique
                    stmt = insert(AttackTechnique).values(
                        id=technique_id,
                        name=technique.get("name", ""),
                        tactic_id=tactic_id,
                        tactic_name=self.TACTIC_DISPLAY_NAMES.get(tactic_short_name, tactic_short_name),
                        parent_id=parent_id,
                        description=technique.get("description"),
                        url=mitre_ref.get("url"),
                        platforms=technique.get("x_mitre_platforms"),
                        data_sources=technique.get("x_mitre_data_sources"),
                        is_subtechnique=is_subtechnique,
                        updated_at=datetime.now(UTC),
                    ).on_conflict_do_update(
                        index_elements=["id"],
                        set_={
                            "name": technique.get("name", ""),
                            "description": technique.get("description"),
                            "url": mitre_ref.get("url"),
                            "platforms": technique.get("x_mitre_platforms"),
                            "data_sources": technique.get("x_mitre_data_sources"),
                            "updated_at": datetime.now(UTC),
                        },
                    )

                    await db.execute(stmt)
                    techniques_count += 1

            await db.commit()

            # Count total techniques
            count_result = await db.execute(select(AttackTechnique))
            total_count = len(count_result.scalars().all())

            logger.info(f"ATT&CK sync complete: {techniques_count} technique upserts, {total_count} total in DB")

            return SyncResult(
                success=True,
                message="ATT&CK data synchronized successfully",
                techniques_updated=total_count,
                new_techniques=0,
            )

        except Exception as e:
            logger.error(f"ATT&CK sync failed: {e}")
            await db.rollback()
            return SyncResult(
                success=False,
                message="ATT&CK sync failed",
                error=str(e),
            )

    def _get_tactic_id(self, attack_data: MitreAttackData, tactic_short_name: str) -> str | None:
        """Get the official tactic ID (e.g., TA0002) for a tactic short name."""
        tactics = attack_data.get_tactics()
        for tactic in tactics:
            # Check kill_chain_phases for matching phase_name
            short_names = [
                phase.get("phase_name")
                for phase in tactic.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            if tactic_short_name in short_names:
                # Get external ID
                for ref in tactic.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        return ref.get("external_id")
        return None


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
    # Extract technique IDs from tags
    technique_ids = extract_attack_tags(tags)

    # Delete existing mappings for this rule
    await db.execute(delete(RuleAttackMapping).where(RuleAttackMapping.rule_id == rule_id))

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
                rule_id=rule_id,
                technique_id=technique_id,
            )
            db.add(mapping)


# Singleton instance
attack_sync_service = AttackSyncService()
