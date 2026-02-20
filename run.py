from universal_security_scanner.cli import run_serve


if __name__ == "__main__":
    raise SystemExit(run_serve("127.0.0.1", 8000, False))
