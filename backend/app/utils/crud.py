"""
Generic CRUD utilities to reduce code duplication.

Provides common CRUD patterns for database operations.
"""
from typing import Any, Generic, TypeVar

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import not_found

ModelType = TypeVar("ModelType")
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)


class CRUDOperations(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """
    Generic CRUD operations for database models.

    Usage:
        class RuleCRUD(CRUDOperations[Rule, RuleCreate, RuleUpdate]):
            pass

        rule_crud = RuleCRUD(Rule)
    """

    def __init__(self, model: type[ModelType]):
        """
        Initialize CRUD operations.

        Args:
            model: SQLAlchemy model class
        """
        self.model = model

    async def get(self, db: AsyncSession, id: Any) -> ModelType | None:
        """
        Get a single record by ID.

        Args:
            db: Database session
            id: Record ID

        Returns:
            Model instance or None
        """
        return await db.get(self.model, id)

    async def get_or_404(self, db: AsyncSession, id: Any, resource_name: str = "Resource") -> ModelType:
        """
        Get a single record by ID or raise 404.

        Args:
            db: Database session
            id: Record ID
            resource_name: Name for error message

        Returns:
            Model instance

        Raises:
            HTTPError: If record not found
        """
        obj = await self.get(db, id)
        if obj is None:
            raise not_found(resource_name, details={"id": str(id)})
        return obj

    async def get_multi(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
    ) -> list[ModelType]:
        """
        Get multiple records with pagination.

        Args:
            db: Database session
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of model instances
        """
        result = await db.execute(select(self.model).offset(skip).limit(limit))
        return list(result.scalars().all())

    async def create(
        self,
        db: AsyncSession,
        obj_in: CreateSchemaType,
    ) -> ModelType:
        """
        Create a new record.

        Args:
            db: Database session
            obj_in: Pydantic schema with creation data

        Returns:
            Created model instance
        """
        obj_in_data = obj_in.model_dump()
        db_obj = self.model(**obj_in_data)
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

    async def update(
        self,
        db: AsyncSession,
        db_obj: ModelType,
        obj_in: UpdateSchemaType | dict[str, Any],
    ) -> ModelType:
        """
        Update an existing record.

        Args:
            db: Database session
            db_obj: Existing model instance
            obj_in: Pydantic schema or dict with update data

        Returns:
            Updated model instance
        """
        if isinstance(obj_in, dict):
            update_data = obj_in
        else:
            update_data = obj_in.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            if hasattr(db_obj, field):
                setattr(db_obj, field, value)

        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

    async def delete(self, db: AsyncSession, id: Any) -> ModelType | None:
        """
        Delete a record by ID.

        Args:
            db: Database session
            id: Record ID

        Returns:
            Deleted model instance or None
        """
        obj = await self.get(db, id)
        if obj:
            await db.delete(obj)
            await db.commit()
        return obj

    async def count(self, db: AsyncSession) -> int:
        """
        Count all records.

        Args:
            db: Database session

        Returns:
            Number of records
        """
        result = await db.execute(select(self.model))
        return len(result.all())


def get_by_id_or_404(
    db: AsyncSession,
    model: type[ModelType],
    id: Any,
    resource_name: str = "Resource",
) -> ModelType:
    """
    Get a record by ID or raise 404.

    Convenience function for simple cases.

    Args:
        db: Database session
        model: SQLAlchemy model class
        id: Record ID
        resource_name: Name for error message

    Returns:
        Model instance

    Raises:
        HTTPError: If record not found
    """
    obj = db.get(model, id)
    if obj is None:
        raise not_found(resource_name, details={"id": str(id)})
    return obj
