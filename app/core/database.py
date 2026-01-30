"""
Database Configuration

SQLAlchemy async engine and session management.
"""

import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.core.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# Convert sync PostgreSQL URL to async
DATABASE_URL = settings.DATABASE_URL.replace('postgresql://', 'postgresql+asyncpg://')

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# Create async session maker
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Base for models
Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting async database sessions.
    
    Usage:
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """
    Initialize database tables.
    
    This creates all tables defined in models.
    In production, use Alembic migrations instead.
    """
    from app.models import Base as ModelsBase
    
    try:
        async with engine.begin() as conn:
            logger.info("Creating database tables...")
            await conn.run_sync(ModelsBase.metadata.create_all)
            logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


async def check_db_connection() -> bool:
    """
    Check if database connection is healthy.
    
    Returns:
        True if connection is healthy, False otherwise
    """
    try:
        async with engine.connect() as conn:
            await conn.execute("SELECT 1")
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False
