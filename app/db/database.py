from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings
from app.db.models import Base


engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
)


SessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db():
    async with engine.begin() as connection:
        await connection.run_sync(
            Base.metadata.create_all
        )


async def get_db():
    async with SessionLocal() as session:
        yield session
