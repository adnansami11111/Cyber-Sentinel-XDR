import asyncio

from sqlalchemy import inspect

from app.db.database import engine, init_db


async def check_database():
    await init_db()

    async with engine.connect() as connection:
        tables = await connection.run_sync(
            lambda sync_connection:
            inspect(sync_connection).get_table_names()
        )

    expected = {
        "assets",
        "security_events",
        "detections",
        "incidents",
        "iocs",
        "response_actions",
    }

    assert expected.issubset(set(tables))


def test_database_schema():
    asyncio.run(check_database())
