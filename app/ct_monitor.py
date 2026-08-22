"""CLI para ejecutar una ronda acotada del monitor de Certificate Transparency."""

from __future__ import annotations

import argparse
import asyncio

from app.config import get_settings
from app.database import create_tables
from app.services.ct_monitor import sync_ct_monitor


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sincroniza el monitor de Certificate Transparency (CT)."
    )
    parser.add_argument("command", choices=["sync"], default="sync", nargs="?")
    parser.parse_args()

    # El runner de Actions usa SQLite efímero. Crear/aplicar el esquema aquí evita
    # que una ronda falle precisamente cuando encuentra un candidato y debe guardar.
    create_tables()
    count = asyncio.run(sync_ct_monitor(get_settings()))
    print(f"observaciones nuevas: {count}")


if __name__ == "__main__":
    main()
