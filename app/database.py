from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _migration_root() -> Path:
    """Encuentra Alembic tanto en un checkout como dentro de un wheel instalado."""
    candidates = (
        Path(__file__).resolve().parents[1],
        Path.cwd(),
        Path("/srv/app"),
    )
    for root in candidates:
        if (root / "alembic.ini").is_file() and (root / "migrations").is_dir():
            return root
    raise RuntimeError("No se encontró el directorio de migraciones de Alembic")


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables() -> None:
    """Aplica el único camino de esquema: Alembic hasta la revisión más reciente."""
    from app import models  # noqa: F401 - registra las tablas para Alembic

    project_root = _migration_root()
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    command.upgrade(config, "head")
