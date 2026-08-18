from __future__ import annotations

import argparse
import asyncio

from app.config import get_settings
from app.database import create_tables
from app.services.threat_intel import sync_all_feeds


def main() -> None:
    parser = argparse.ArgumentParser(description="Sincroniza feeds de dominios maliciosos.")
    parser.add_argument("command", choices=["sync"], default="sync", nargs="?")
    parser.parse_args()
    create_tables()
    results = asyncio.run(sync_all_feeds(get_settings()))
    for provider, count in results.items():
        print(f"{provider}: {count} indicadores activos importados")


if __name__ == "__main__":
    main()
