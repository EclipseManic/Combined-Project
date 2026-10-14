from datetime import datetime
from typing import Optional
from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("value", name="uq_ioc_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column("ioc_type", String(50), nullable=False)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    lookup_results: Mapped[list["LookupResult"]] = relationship("LookupResult", back_populates="ioc", lazy="selectin", cascade="all, delete-orphan")
    investigation_iocs: Mapped[list["InvestigationIOC"]] = relationship("InvestigationIOC", back_populates="ioc", lazy="selectin", cascade="all, delete-orphan")


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    iocs: Mapped[list["InvestigationIOC"]] = relationship("InvestigationIOC", back_populates="investigation", lazy="selectin", cascade="all, delete-orphan")


class InvestigationIOC(Base):
    __tablename__ = "investigation_iocs"
    __table_args__ = (
        UniqueConstraint("investigation_id", "ioc_id", name="uq_investigation_ioc"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), nullable=False, index=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"), nullable=False, index=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="iocs")
    ioc: Mapped["IOC"] = relationship("IOC", back_populates="investigation_iocs")


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    events: Mapped[str] = mapped_column(Text, nullable=False)
    secret: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class IOCFeedback(Base):
    __tablename__ = "ioc_feedback"
    __table_args__ = (UniqueConstraint("ioc_value", name="uq_ioc_feedback_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    feedback: Mapped[str] = mapped_column(String(20), nullable=False, default="false_positive")
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


class LookupResult(Base):
    __tablename__ = "lookup_results"
    __table_args__ = (
        UniqueConstraint("task_id", name="uq_lookup_results_task_id"),
        Index("ix_lookup_results_ioc_task", "ioc_id", "task_id"),
        Index("ix_lookup_results_created_at", "created_at"),
        Index("ix_lookup_results_ioc_created", "ioc_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    batch_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    composite_score: Mapped[float] = mapped_column(Float, default=0.0)
    composite_verdict: Mapped[str] = mapped_column(String(20), default="unknown")
    composite_confidence: Mapped[str] = mapped_column(String(10), default="low")
    full_response: Mapped[Optional[Text]] = mapped_column(Text, nullable=True)
    source_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    ioc: Mapped["IOC"] = relationship("IOC", back_populates="lookup_results")


class BatchRecord(Base):
    __tablename__ = "batches"
    __table_args__ = (Index("ix_batches_status_created", "status", "created_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    total: Mapped[int] = mapped_column(Integer, default=0)
    completed: Mapped[int] = mapped_column(Integer, default=0)
    summary_json: Mapped[Optional[str]] = mapped_column(Text, default="{}")
    result_json: Mapped[Optional[str]] = mapped_column(Text, default="{}")
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
