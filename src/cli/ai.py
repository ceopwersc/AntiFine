"""Developer utilities for AntiFine's local AI knowledge index."""

from __future__ import annotations

import argparse

from src.ai.retriever import rebuild_index


def main() -> int:
    parser = argparse.ArgumentParser(prog="antifine ai")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("rebuild-index", help="rebuild the local AI knowledge index")
    args = parser.parse_args()
    if args.command == "rebuild-index":
        chunks = rebuild_index()
        print(f"Rebuilt AntiFine AI knowledge index with {len(chunks)} chunks.")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
