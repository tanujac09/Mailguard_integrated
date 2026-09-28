from typing import Optional, Any, List
from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class StepOut(BaseModel):
    step_key: str
    title: str
    status: str
    summary: str
    details: Any
    order_index: int

    class Config:
        from_attributes = True


class EmailListItem(BaseModel):
    id: int
    filename: str
    sender: Optional[str]
    subject: Optional[str]
    fraud_score: float
    verdict: str
    flagged: int
    created_at: str
    origin_country: Optional[str]

    class Config:
        from_attributes = True


class EmailDetail(BaseModel):
    id: int
    filename: str
    sha256: str
    sender: Optional[str]
    reply_to: Optional[str]
    return_path: Optional[str]
    subject: Optional[str]
    date_header: Optional[str]
    raw_headers: Optional[str]
    body_preview: Optional[str]
    fraud_score: float
    verdict: str
    flagged: int
    origin_ip: Optional[str]
    origin_country: Optional[str]
    origin_city: Optional[str]
    origin_lat: Optional[float]
    origin_lon: Optional[float]
    origin_isp: Optional[str]
    origin_is_proxy: int
    created_at: str
    steps: List[StepOut]

    class Config:
        from_attributes = True
