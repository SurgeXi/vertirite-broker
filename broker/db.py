# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)


@contextmanager
def session_scope() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Register every SQLAlchemy model so Base.metadata is complete.

    Schema creation is the responsibility of alembic, NOT this function.
    Run `alembic upgrade head` before starting the broker. Previously this
    called Base.metadata.create_all() as a side effect, which produced
    schema drift between dev installs and migration-managed prod installs.
    Removed 2026-05-20.
    """
    from . import tables  # noqa: F401
    from . import tenant  # noqa: F401  — registers tenant/user/usage tables
    from . import peer_stream  # noqa: F401 — registers unprompted_messages
    from . import support  # noqa: F401 — registers support_tickets
    from . import fleet_manifest  # noqa: F401 — registers fleet_hosts table
    from . import discovery  # noqa: F401 — registers witnessed_findings table
    from . import reports  # noqa: F401 — registers report_runs table
    from . import intelligence  # noqa: F401 — registers intelligence_catalogs + clock
    from . import protection  # noqa: F401 — registers protection_instance (self-narc)
    from . import licensing  # noqa: F401 — registers the license table
    from . import governor_store  # noqa: F401 — registers governor_state (gate 01 local mode authority)
