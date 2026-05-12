"""
Wait until the AI Service responds with HTTP 200 on /health.
Exits 0 when healthy, 1 on timeout.

The API Gateway (Azure APIM) is cloud-hosted and does not need local polling.

Can be called with --services to override URLs:
    python wait_for_services.py --services http://localhost:8001/health
"""
import argparse
import sys
import time
import urllib.request
import urllib.error

# Default: only poll local AI service; APIM is Azure-hosted
DEFAULT_SERVICES = {
    "AI Service": "http://localhost:8001/health",
}
TIMEOUT_SECS  = 120
POLL_INTERVAL = 3


def check(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=4) as r:
            return r.status == 200
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--services", nargs="*",
        help="Health URLs to poll (default: AI Service on :8001)"
    )
    args = parser.parse_args()

    if args.services:
        services = {url: url for url in args.services}
    else:
        services = DEFAULT_SERVICES

    pending = dict(services)
    deadline = time.time() + TIMEOUT_SECS

    while pending and time.time() < deadline:
        still_pending = {}
        for name, url in pending.items():
            if check(url):
                print(f"  ✓ {name} is healthy ({url})")
            else:
                still_pending[name] = url
        pending = still_pending
        if pending:
            waiting = ", ".join(pending.keys())
            elapsed = int(time.time() - (deadline - TIMEOUT_SECS))
            print(f"  ⏳ Waiting for: {waiting} ({elapsed}s elapsed)...")
            time.sleep(POLL_INTERVAL)

    if pending:
        print(f"\n✗ Timeout! Services not healthy: {list(pending.keys())}")
        print("  Check logs: docker compose logs ai-service")
        sys.exit(1)

    print("\n  All services healthy — proceeding with experiment.")
    sys.exit(0)


if __name__ == "__main__":
    main()
