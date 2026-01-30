"""Database connection and session management."""

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool

from app.core.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

# Create declarative base for models
Base = declarative_base()

# Global engine and session maker
engine: AsyncEngine | None = None
SessionLocal: async_sessionmaker[AsyncSession] | None = None


async def init_database() -> None:
    """Initialize database connection pool."""
    global engine, SessionLocal
    
    logger.info("initializing_database_connection")
    
    # Convert PostgresDsn to async URL
    db_url = str(settings.DATABASE_URL)
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    
    engine = create_async_engine(
        db_url,
        echo=settings.DB_ECHO,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_pre_ping=True,
        poolclass=NullPool if settings.DEBUG else None,
    )
    
    SessionLocal = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    
    # Create tables (in production, use Alembic migrations)
    if settings.DEBUG:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    logger.info("database_initialized")


async def close_database() -> None:
    """Close database connections."""
    global engine
    
    if engine:
        logger.info("closing_database_connections")
        await engine.dispose()
        logger.info("database_connections_closed")


async def get_db() -> AsyncSession:
    """Dependency for getting database sessions."""
    if SessionLocal is None:
        raise RuntimeError("Database not initialized")
    
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()