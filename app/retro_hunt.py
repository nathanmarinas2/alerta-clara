from __future__ import annotations

import json

from app.database import SessionLocal, create_tables
from app.services.retrohunt import run_retro_hunt


def main() -> None:
    create_tables()
    with SessionLocal() as db:
        result = run_retro_hunt(db)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
