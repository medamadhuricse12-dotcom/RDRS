from pathlib import Path
from datetime import datetime, timezone

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "rdrs.db"


engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

Base = declarative_base()


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True)
    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
    )
    event_type = Column(String(100), nullable=False)
    file_path = Column(Text)
    entropy = Column(Float)
    threat_score = Column(Float, default=0)
    severity = Column(String(30))
    status = Column(String(30), default="open")
    details = Column(Text)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
    )
    severity = Column(String(30), nullable=False)
    threat_score = Column(Float, default=0)
    message = Column(Text, nullable=False)
    status = Column(String(30), default="open")


class FileEvent(Base):
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
    )
    event_type = Column(String(50), nullable=False)
    file_path = Column(Text, nullable=False)
    entropy = Column(Float)
    details = Column(Text)


class Process(Base):
    __tablename__ = "processes"

    id = Column(Integer, primary_key=True)
    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
    )
    pid = Column(Integer, nullable=False)
    name = Column(String(255))
    cpu_percent = Column(Float, default=0.0)
    memory_percent = Column(Float, default=0.0)
    exe_path = Column(Text)
    parent_pid = Column(Integer)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_session():
    return SessionLocal()
