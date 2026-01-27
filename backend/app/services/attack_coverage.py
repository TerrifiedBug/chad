"""
ATT&CK coverage calculation service.

Provides coverage metrics for the matrix visualization.
"""
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.attack_technique import AttackTechnique, RuleAttackMapping
from app.models.rule import Rule, RuleStatus
from app.schemas.attack import (
    CoverageResponse,
    LinkedRuleResponse,
    MatrixResponse,
    TacticWithTechniques,
    TechniqueCoverageStats,
    TechniqueDetailResponse,
    TechniqueResponse,
    TechniqueWithCoverage,
)


class AttackCoverageService:
    """Service for calculating ATT&CK coverage metrics."""

    async def get_matrix_structure(self, db: AsyncSession) -> MatrixResponse:
        """
        Get the full matrix structure grouped by tactic.

        Returns all techniques grouped into their tactic columns.
        """
        # Fetch all techniques ordered by tactic
        result = await db.execute(
            select(AttackTechnique).order_by(AttackTechnique.tactic_id, AttackTechnique.id)
        )
        techniques = result.scalars().all()

        # Group by tactic
        tactics_dict: dict[str, TacticWithTechniques] = {}

        for tech in techniques:
            if tech.tactic_id not in tactics_dict:
                tactics_dict[tech.tactic_id] = TacticWithTechniques(
                    id=tech.tactic_id,
                    name=tech.tactic_name,
                    techniques=[],
                )

            tactics_dict[tech.tactic_id].techniques.append(
                TechniqueWithCoverage(
                    id=tech.id,
                    name=tech.name,
                    tactic_id=tech.tactic_id,
                    tactic_name=tech.tactic_name,
                    parent_id=tech.parent_id,
                    is_subtechnique=tech.is_subtechnique,
                    rule_count=0,  # Coverage filled separately
                )
            )

        # Sort tactics by ID (TA0001, TA0002, etc.)
        sorted_tactics = sorted(tactics_dict.values(), key=lambda t: t.id)

        return MatrixResponse(tactics=sorted_tactics)

    async def get_coverage(
        self,
        db: AsyncSession,
        deployed_only: bool = False,
        severity: list[str] | None = None,
        index_pattern_id: UUID | None = None,
    ) -> CoverageResponse:
        """
        Get coverage counts per technique with optional filters.

        Returns both total and deployed counts per technique.

        Args:
            deployed_only: Only count deployed rules
            severity: Filter by severity levels
            index_pattern_id: Filter by specific index pattern
        """
        # Build the base query for total counts
        total_query = (
            select(
                RuleAttackMapping.technique_id,
                func.count(RuleAttackMapping.rule_id.distinct()).label("count"),
            )
            .join(Rule, Rule.id == RuleAttackMapping.rule_id)
            .group_by(RuleAttackMapping.technique_id)
        )

        # Build the query for deployed counts
        deployed_query = (
            select(
                RuleAttackMapping.technique_id,
                func.count(RuleAttackMapping.rule_id.distinct()).label("count"),
            )
            .join(Rule, Rule.id == RuleAttackMapping.rule_id)
            .where(Rule.status == RuleStatus.DEPLOYED)
            .group_by(RuleAttackMapping.technique_id)
        )

        # Apply common filters
        if severity:
            total_query = total_query.where(Rule.severity.in_(severity))
            deployed_query = deployed_query.where(Rule.severity.in_(severity))

        if index_pattern_id:
            total_query = total_query.where(Rule.index_pattern_id == index_pattern_id)
            deployed_query = deployed_query.where(Rule.index_pattern_id == index_pattern_id)

        # If deployed_only filter is set, both queries return deployed counts only
        if deployed_only:
            total_query = total_query.where(Rule.status == RuleStatus.DEPLOYED)

        # Execute both queries
        total_result = await db.execute(total_query)
        deployed_result = await db.execute(deployed_query)

        total_rows = total_result.all()
        deployed_rows = deployed_result.all()

        # Build coverage dict with both counts
        total_counts = {row.technique_id: row.count for row in total_rows}
        deployed_counts = {row.technique_id: row.count for row in deployed_rows}

        # Fetch all techniques to aggregate sub-technique counts into parents
        tech_result = await db.execute(select(AttackTechnique))
        all_techniques = tech_result.scalars().all()

        # Build parent-child map
        parent_map: dict[str, str | None] = {tech.id: tech.parent_id for tech in all_techniques}

        # Aggregate sub-technique counts into parent techniques
        aggregated_total: dict[str, int] = {}
        aggregated_deployed: dict[str, int] = {}

        for tech_id, count in total_counts.items():
            # Add count to the technique itself
            if tech_id not in aggregated_total:
                aggregated_total[tech_id] = 0
            aggregated_total[tech_id] += count

            # If this is a sub-technique, add count to its parent
            parent_id = parent_map.get(tech_id)
            if parent_id:
                if parent_id not in aggregated_total:
                    aggregated_total[parent_id] = 0
                aggregated_total[parent_id] += count

        for tech_id, count in deployed_counts.items():
            # Add count to the technique itself
            if tech_id not in aggregated_deployed:
                aggregated_deployed[tech_id] = 0
            aggregated_deployed[tech_id] += count

            # If this is a sub-technique, add count to its parent
            parent_id = parent_map.get(tech_id)
            if parent_id:
                if parent_id not in aggregated_deployed:
                    aggregated_deployed[parent_id] = 0
                aggregated_deployed[parent_id] += count

        # Combine into coverage response
        all_technique_ids = set(aggregated_total.keys()) | set(aggregated_deployed.keys())
        coverage = {
            tech_id: TechniqueCoverageStats(
                total=aggregated_total.get(tech_id, 0),
                deployed=aggregated_deployed.get(tech_id, 0),
            )
            for tech_id in all_technique_ids
        }

        return CoverageResponse(coverage=coverage)

    async def get_technique_detail(
        self,
        db: AsyncSession,
        technique_id: str,
        deployed_only: bool = False,
        severity: list[str] | None = None,
        index_pattern_id: UUID | None = None,
    ) -> TechniqueDetailResponse | None:
        """
        Get full technique details with linked rules.
        """
        # Fetch technique
        result = await db.execute(
            select(AttackTechnique).where(AttackTechnique.id == technique_id)
        )
        technique = result.scalar_one_or_none()

        if not technique:
            return None

        # Build query for linked rules
        rules_query = (
            select(Rule)
            .join(RuleAttackMapping, RuleAttackMapping.rule_id == Rule.id)
            .where(RuleAttackMapping.technique_id == technique_id)
        )

        if deployed_only:
            rules_query = rules_query.where(Rule.status == RuleStatus.DEPLOYED)

        if severity:
            rules_query = rules_query.where(Rule.severity.in_(severity))

        if index_pattern_id:
            rules_query = rules_query.where(Rule.index_pattern_id == index_pattern_id)

        rules_result = await db.execute(rules_query)
        rules = rules_result.scalars().all()

        # Get sub-techniques if this is a parent technique
        sub_techniques: list[TechniqueWithCoverage] = []
        if not technique.is_subtechnique:
            sub_result = await db.execute(
                select(AttackTechnique).where(AttackTechnique.parent_id == technique_id)
            )
            for sub in sub_result.scalars().all():
                # Get rule count for sub-technique
                count_result = await db.execute(
                    select(func.count(RuleAttackMapping.rule_id.distinct())).where(
                        RuleAttackMapping.technique_id == sub.id
                    )
                )
                count = count_result.scalar() or 0

                sub_techniques.append(
                    TechniqueWithCoverage(
                        id=sub.id,
                        name=sub.name,
                        tactic_id=sub.tactic_id,
                        tactic_name=sub.tactic_name,
                        parent_id=sub.parent_id,
                        is_subtechnique=True,
                        rule_count=count,
                    )
                )

        return TechniqueDetailResponse(
            technique=TechniqueResponse(
                id=technique.id,
                name=technique.name,
                tactic_id=technique.tactic_id,
                tactic_name=technique.tactic_name,
                parent_id=technique.parent_id,
                description=technique.description,
                url=technique.url,
                platforms=technique.platforms,
                data_sources=technique.data_sources,
                is_subtechnique=technique.is_subtechnique,
                updated_at=technique.updated_at,
            ),
            rules=[
                LinkedRuleResponse(
                    id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    status=rule.status.value,
                    index_pattern_name=None,  # Could eager load if needed
                )
                for rule in rules
            ],
            sub_techniques=sub_techniques,
        )

    async def get_technique_count(self, db: AsyncSession) -> int:
        """Get total count of cached techniques."""
        result = await db.execute(select(func.count(AttackTechnique.id)))
        return result.scalar() or 0


# Singleton instance
attack_coverage_service = AttackCoverageService()
