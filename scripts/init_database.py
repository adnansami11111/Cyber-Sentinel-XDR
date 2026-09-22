import asyncio

from app.db.database import init_db


async def main():
    await init_db()
    print("Cyber Sentinel XDR database initialized successfully.")


if __name__ == "__main__":
    asyncio.run(main())
