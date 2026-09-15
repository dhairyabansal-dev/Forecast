from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_blockchain_service, get_current_user, get_db_session, require_roles
from app.core.constants import DEFAULT_PAGE_SIZE, EvidenceStatus, MAX_PAGE_SIZE
from app.database.repositories.evidence_repository import EvidenceRepository
from app.models.evidence import Evidence
from app.models.user import User
from app.schemas.evidence import EvidenceCreate, EvidenceListResponse, EvidenceResponse, EvidenceVerifyResponse
from app.services.blockchain_service import BlockchainService
from app.utils.helpers import utc_now

router = APIRouter(prefix="/evidence", tags=["Evidence"])


@router.post("", response_model=EvidenceResponse, status_code=201)
async def create_evidence(payload: EvidenceCreate, user: User = Depends(require_roles("ADMIN", "DATA_SCIENTIST")), session: AsyncSession = Depends(get_db_session), blockchain: BlockchainService = Depends(get_blockchain_service)):
    repo = EvidenceRepository(session)
    content_hash = blockchain.compute_evidence_hash(payload.payload)
    evidence = Evidence(threat_id=payload.threat_id, title=payload.title, description=payload.description, payload=payload.payload, content_hash=content_hash, status=EvidenceStatus.HASHED.value)
    return await repo.create(evidence)


@router.post("/{evidence_id}/anchor", response_model=EvidenceResponse)
async def anchor_evidence(evidence_id: str, user: User = Depends(require_roles("ADMIN", "DATA_SCIENTIST")), session: AsyncSession = Depends(get_db_session), blockchain: BlockchainService = Depends(get_blockchain_service)):
    repo = EvidenceRepository(session)
    evidence = await repo.get_by_id(evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    try:
        result = blockchain.anchor_evidence(evidence.content_hash)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return await repo.update(evidence, status=EvidenceStatus.ANCHORED.value, blockchain_tx_hash=result["tx_hash"], blockchain_block_number=result["block_number"], anchored_at=result["anchored_at"])


@router.get("/{evidence_id}/verify", response_model=EvidenceVerifyResponse)
async def verify_evidence(evidence_id: str, user: User = Depends(get_current_user), session: AsyncSession = Depends(get_db_session), blockchain: BlockchainService = Depends(get_blockchain_service)):
    repo = EvidenceRepository(session)
    evidence = await repo.get_by_id(evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if evidence.status != EvidenceStatus.ANCHORED.value:
        return EvidenceVerifyResponse(evidence_id=evidence_id, is_valid=False, on_chain_hash=None, local_hash=evidence.content_hash, checked_at=utc_now(), message="Evidence has not been anchored on-chain yet.")
    try:
        is_valid = blockchain.verify_evidence(evidence.content_hash)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return EvidenceVerifyResponse(evidence_id=evidence_id, is_valid=is_valid, on_chain_hash=evidence.content_hash if is_valid else None, local_hash=evidence.content_hash, checked_at=utc_now(), message="Verified on-chain." if is_valid else "Hash mismatch or not found on-chain.")


@router.get("", response_model=EvidenceListResponse)
async def list_evidence(page: int = Query(1, ge=1), page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE), threat_id: str | None = None, status: str | None = None, user: User = Depends(get_current_user), session: AsyncSession = Depends(get_db_session)):
    repo = EvidenceRepository(session)
    items, total = await repo.list(page=page, page_size=page_size, threat_id=threat_id, status=status)
    return EvidenceListResponse(items=items, total=total, page=page, page_size=page_size, total_pages=(total + page_size - 1) // page_size if total else 0)


@router.get("/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(evidence_id: str, user: User = Depends(get_current_user), session: AsyncSession = Depends(get_db_session)):
    repo = EvidenceRepository(session)
    evidence = await repo.get_by_id(evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence
