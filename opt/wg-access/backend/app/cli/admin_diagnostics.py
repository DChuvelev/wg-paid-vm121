"""Bounded VM130→VM121 fixed worker CLI, via operator SSH + docker exec.

Usage:
  python -m app.cli.admin_diagnostics claim
  python -m app.cli.admin_diagnostics complete <job-uuid> <lease-uuid> < ZIP
  python -m app.cli.admin_diagnostics fail <job-uuid> <lease-uuid> <safe-code>
No arbitrary command, path, URL, user id or shell text accepted.
"""
from __future__ import annotations
import sys
import uuid
from app.db.session import SessionLocal
from app.services.admin_diagnostics import claim, finalize, fail, MAX_ZIP_BYTES, DiagnosticRejected


def main(argv: list[str]) -> int:
    try:
        if argv == ["claim"]:
            with SessionLocal() as db:
                work = claim(db)
            if work is None:
                print("RESULT=NO_PENDING_JOB")
            else:
                print(f"RESULT=CLAIMED JOB_ID={work[0]} LEASE={work[1]}")
            return 0
        if len(argv) == 3 and argv[0] == "complete":
            job_id, lease = map(uuid.UUID, argv[1:])
            raw = sys.stdin.buffer.read(MAX_ZIP_BYTES + 1)
            with SessionLocal() as db:
                status = finalize(db, job_id, lease, raw)
            print(f"RESULT=PASS_COMPLETE STATUS={status}")
            return 0
        if len(argv) == 4 and argv[0] == "fail":
            job_id, lease = map(uuid.UUID, argv[1:3])
            with SessionLocal() as db:
                fail(db, job_id, lease, argv[3])
            print("RESULT=PASS_FAIL_RECORDED")
            return 0
    except (DiagnosticRejected, ValueError) as exc:
        print(f"RESULT=STOP_DIAGNOSTICS_WORKER REASON={str(exc)}", file=sys.stderr)
        return 2
    print("RESULT=STOP_INVALID_CLI_ACTION", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
