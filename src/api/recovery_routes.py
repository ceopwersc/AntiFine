"""Authenticated recovery operations over backend-owned backup identities."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from starlette.concurrency import run_in_threadpool
from typing import Any, Callable

from src.services.recovery_inspection import RecoveryConflict, UnknownBackup, inspect_backup, list_backups
from src.services.restoration_service import preview_restore, restore
from src.services.scan_repository import ScanRepository
from src.services.settings import database_path

router = APIRouter(prefix='/api')


class RestoreRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    preview_id: str = Field(pattern='^[0-9a-f]{64}$', max_length=64)
    confirmed: StrictBool


async def _execute(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        return await run_in_threadpool(function, ScanRepository(database_path()), *args, **kwargs)
    except UnknownBackup:
        raise HTTPException(404, 'Backup unavailable') from None
    except RecoveryConflict:
        raise HTTPException(409, 'Recovery needs review: stale source, unavailable backup, invalid preview or interrupted operation. Inspect again.') from None
    except (OSError, ValueError):
        raise HTTPException(409, 'Recovery evidence or private storage is unavailable; manual review is required.') from None


@router.get('/backups')
async def backups() -> dict:
    return {'backups': await _execute(list_backups)}


@router.get('/backups/{backup_id}')
async def backup(backup_id: str) -> dict:
    return await _execute(inspect_backup, backup_id)


@router.post('/backups/{backup_id}/restore/preview')
async def preview(backup_id: str) -> dict:
    return await _execute(preview_restore, backup_id)


@router.post('/backups/{backup_id}/restore')
async def apply_restore(backup_id: str, request: RestoreRequest) -> dict:
    if request.confirmed is not True:
        raise HTTPException(422, 'Restoration requires explicit confirmation of the current preview')
    return await _execute(restore, backup_id, request.preview_id, confirmed=request.confirmed)


@router.get('/restorations')
async def restorations() -> dict:
    return {'restorations': await run_in_threadpool(ScanRepository(database_path()).restorations)}
