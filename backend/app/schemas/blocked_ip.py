from datetime import datetime
from uuid import UUID
from pydantic import BaseModel

class BlockedIpBase(BaseModel):
    ip: str
    rule_name: str
    reason: str
    is_active: bool = True

class BlockedIpCreate(BlockedIpBase):
    pass

class BlockedIpResponse(BlockedIpBase):
    id: UUID
    block_count: int
    unblock_reason: str | None = None
    unblocked_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    created_by: str | None = None
    updated_by: str | None = None

    class Config:
        from_attributes = True
