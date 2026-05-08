import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import String, Text, Float, Integer, DateTime, Boolean, JSON
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class MLModel(Base):
    __tablename__ = "ml_models"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    model_type: Mapped[str] = mapped_column(
        String(50), index=True, nullable=False
    )  # autoencoder, isolation_forest, gnn, transformer, xgboost
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    framework: Mapped[str] = mapped_column(String(50), default="pytorch")  # pytorch, sklearn, xgboost
    status: Mapped[str] = mapped_column(
        String(30), default="training", index=True
    )  # training, active, deprecated, failed
    description: Mapped[Optional[str]] = mapped_column(Text)
    hyperparameters: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    metrics: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    # Detection rates
    precision: Mapped[Optional[float]] = mapped_column(Float)
    recall: Mapped[Optional[float]] = mapped_column(Float)
    f1_score: Mapped[Optional[float]] = mapped_column(Float)
    false_positive_rate: Mapped[Optional[float]] = mapped_column(Float)
    # Storage
    model_path: Mapped[Optional[str]] = mapped_column(String(500))  # S3/GCS path
    model_size_bytes: Mapped[Optional[int]] = mapped_column(Integer)
    input_features: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    training_dataset_hash: Mapped[Optional[str]] = mapped_column(String(64))
    training_samples: Mapped[Optional[int]] = mapped_column(Integer)
    is_federated: Mapped[bool] = mapped_column(Boolean, default=False)
    federated_rounds: Mapped[Optional[int]] = mapped_column(Integer)
    deployed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class FederatedRound(Base):
    __tablename__ = "federated_rounds"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )
    round_number: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    num_samples: Mapped[int] = mapped_column(Integer, default=0)
    local_loss: Mapped[float] = mapped_column(Float, default=0.0)
    local_accuracy: Mapped[Optional[float]] = mapped_column(Float)
    global_loss: Mapped[Optional[float]] = mapped_column(Float)
    global_accuracy: Mapped[Optional[float]] = mapped_column(Float)
    weights_hash: Mapped[Optional[str]] = mapped_column(String(64))  # SHA-256 of weights
    communication_size_bytes: Mapped[Optional[int]] = mapped_column(Integer)
    training_time_seconds: Mapped[Optional[float]] = mapped_column(Float)
    status: Mapped[str] = mapped_column(
        String(30), default="in_progress", index=True
    )  # in_progress, completed, failed
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class AnomalyScore(Base):
    __tablename__ = "anomaly_scores"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    log_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), index=True)
    flow_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), index=True)
    model_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, index=True, nullable=False)  # 0.0 - 1.0
    reconstruction_error: Mapped[Optional[float]] = mapped_column(Float)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    threshold_used: Mapped[float] = mapped_column(Float, default=0.95)
    feature_scores: Mapped[Optional[Dict[str, float]]] = mapped_column(JSON)
    inference_time_ms: Mapped[Optional[float]] = mapped_column(Float)
    explanation: Mapped[Optional[str]] = mapped_column(Text)  # SHAP/LIME explanation
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class TrainingJob(Base):
    __tablename__ = "training_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    model_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), index=True)
    job_type: Mapped[str] = mapped_column(
        String(50), index=True, nullable=False
    )  # full_training, incremental, federated, fine_tune
    ray_job_id: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(
        String(30), default="queued", index=True
    )  # queued, running, completed, failed, cancelled
    dataset_info: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    hyperparameters: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    resources: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    # Progress
    current_epoch: Mapped[Optional[int]] = mapped_column(Integer)
    total_epochs: Mapped[Optional[int]] = mapped_column(Integer)
    current_round: Mapped[Optional[int]] = mapped_column(Integer)
    total_rounds: Mapped[Optional[int]] = mapped_column(Integer)
    progress_percent: Mapped[float] = mapped_column(Float, default=0.0)
    # Results
    train_loss: Mapped[Optional[List[float]]] = mapped_column(ARRAY(Float))
    val_loss: Mapped[Optional[List[float]]] = mapped_column(ARRAY(Float))
    final_metrics: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    model_artifact_path: Mapped[Optional[str]] = mapped_column(String(500))
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float)
    cost_estimate: Mapped[Optional[float]] = mapped_column(Float)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )