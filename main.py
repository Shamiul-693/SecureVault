"""SecureVault — offline desktop password manager.

Run from source:   python main.py
"""
import sys


def main() -> int:
    from app.application import run
    return run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
