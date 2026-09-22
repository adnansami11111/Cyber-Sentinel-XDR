from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.intelligence.ingestion import ingest_batch


router = APIRouter(
    prefix="/api/intelligence",
    tags=["Threat Intelligence"],
)


class IOCIngestItem(BaseModel):
    indicator_type: str
    value: str
    reputation: str = "UNKNOWN"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    source: str | None = None
    threat_type: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    tags: list[str] = Field(default_factory=list)


class IOCIngestRequest(BaseModel):
    records: list[IOCIngestItem]


@router.post("/ingest")
async def ingest_iocs(
    request: IOCIngestRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    if not request.records:
        raise HTTPException(
            status_code=400,
            detail="At least one IOC record is required",
        )

    records = [
        item.model_dump(exclude_none=True)
        for item in request.records
    ]

    result = await ingest_batch(db, records)

    return {
        "status": "completed",
        "pipeline": "CTI_INGESTION",
        "mode": "LAB",
        **result,
    }
