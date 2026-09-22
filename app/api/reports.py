from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.reporting.service import build_incident_report
from app.reporting.html import render_incident_report_html
from app.reporting.pdf import render_incident_report_pdf

router = APIRouter(
    prefix="/api/reports",
    tags=["Security Reports"],
)


@router.get("/incident/{incident_id}")
async def get_incident_report(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    if incident_id <= 0:
        raise HTTPException(
            status_code=400,
            detail="incident_id must be a positive integer",
        )

    report = await build_incident_report(
        db=db,
        incident_id=incident_id,
    )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident {incident_id} not found",
        )

    return {
        "status": "REPORT_READY",
        "report": report,
    }


@router.get(
    "/incident/{incident_id}/html",
    response_class=HTMLResponse,
)
async def get_incident_report_html(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    if incident_id <= 0:
        raise HTTPException(
            status_code=400,
            detail="incident_id must be a positive integer",
        )

    report = await build_incident_report(
        db=db,
        incident_id=incident_id,
    )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident {incident_id} not found",
        )

    return HTMLResponse(
        content=render_incident_report_html(report),
        status_code=200,
    )


@router.get(
    "/incident/{incident_id}/pdf",
)
async def get_incident_report_pdf(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    if incident_id <= 0:
        raise HTTPException(
            status_code=400,
            detail="incident_id must be a positive integer",
        )

    report = await build_incident_report(
        db=db,
        incident_id=incident_id,
    )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident {incident_id} not found",
        )

    pdf_bytes = render_incident_report_pdf(report)

    filename = f"cyber-sentinel-incident-{incident_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )
