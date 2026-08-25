from datetime import datetime

from pydantic import BaseModel, Field


class AuthEventCreate(BaseModel):
    user_id: str = Field(min_length=1, max_length=120)
    timestamp: datetime
    ip_address: str = Field(min_length=3, max_length=64)
    country: str = Field(min_length=1, max_length=80)
    city: str = Field(min_length=1, max_length=120)
    device_id: str = Field(min_length=1, max_length=120)
    success: bool = True
    source: str = Field(default="application", min_length=1, max_length=80)


class AlertStatusUpdate(BaseModel):
    status: str = Field(pattern="^(OPEN|ACKNOWLEDGED|RESOLVED)$")
