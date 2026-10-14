from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    detail: str
    error_code: str | None = None
    request_id: str | None = None


class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    progress: float = 0.0
    stages: list[dict[str, object]] = Field(default_factory=list)
    ioc_value: str
    normalized: str
    ioc_type: str


class BatchStatusResponse(BaseModel):
    batch_id: str
    total: int
    status: str


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str


class CacheClearResponse(BaseModel):
    status: str


class InvestigationSummary(BaseModel):
    id: int
    name: str
    description: str
    ioc_count: int
    created_at: str | None = None
    updated_at: str | None = None


class InvestigationCreateResponse(BaseModel):
    id: int
    name: str
    description: str
    created_at: str | None = None


class IOCInInvestigation(BaseModel):
    id: int
    ioc_id: int
    value: str
    ioc_type: str
    notes: str
    score: float | None = None
    verdict: str | None = None
    looked_up_at: str | None = None


class InvestigationDetail(BaseModel):
    id: int
    name: str
    description: str
    iocs: list[IOCInInvestigation]
    created_at: str | None = None
    updated_at: str | None = None


class StatusResponse(BaseModel):
    status: str


class RecentIOCResponse(BaseModel):
    id: int
    value: str
    ioc_type: str
    verdict: str | None = None
    score: float | None = None
    confidence: str | None = None
    created_at: str | None = None


class WebhookResponse(BaseModel):
    id: str
    url: str
    events: list[str]
    has_secret: bool = False
    created_at: str | None = None


class FeedbackRequest(BaseModel):
    ioc: str
    ioc_type: str | None = None
    feedback: str = "false_positive"
    note: str | None = None


class FeedbackResponse(BaseModel):
    ioc_value: str
    feedback: str
    note: str | None = None
    created_at: str | None = None


class SaveResponse(BaseModel):
    status: str
    ioc_id: int
