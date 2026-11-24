"""Command-line entry point.

Two modes mirror the two places this runs:

  scan    a single .ics/.eml, for testing and for the review queue
  filter  a maildir/gateway queue: read a message on stdin, write the message
          (possibly rewritten) plus a one-line JSON verdict on stdout

The ``filter`` exit status is what a milter or Postfix ``content_filter`` acts
on: 0 deliver the bytes on stdout, 10 deliver to review, 20 drop.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import mime, process
from .auth import parse_authentication_results
from .policy import Organisation, Policy
from .risk import Disposition, MailContext
from .trust import TrustStore

EXIT_DELIVER = 0
EXIT_REVIEW = 10
EXIT_DROP = 20


def _policy_from_args(args) -> Policy:
    org = Organisation()
    if args.org_domain:
        org.domains = {d.strip().lower() for d in args.org_domain.split(",") if d.strip()}
    if args.org_name:
        org.name = args.org_name
    return Policy(org=org)


def _exit_for(disposition: Disposition) -> int:
    if disposition == Disposition.REJECT:
        return EXIT_DROP
    if disposition == Disposition.QUARANTINE:
        return EXIT_REVIEW
    return EXIT_DELIVER


def _emit(payload: dict, *, as_json: bool) -> None:
    if as_json:
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return
    print(f"decision : {payload.get('disposition', payload.get('worst_disposition'))}")
    print(f"status   : {payload.get('status', '')}")
    if payload.get("score") is not None:
        print(f"score    : {payload['score']}")
    for reason in payload.get("reasons", []) or payload.get("findings", []):
        print(f"  - {reason}")
    links = payload.get("links") or []
    for link in links:
        if link.get("signals"):
            print(f"  link {link['host']} risk={link['risk']}")
            for signal in link["signals"]:
                print(f"    * {signal['detail']}")


def cmd_scan(args) -> int:
    path = Path(args.path)
    raw = sys.stdin.buffer.read() if str(path) == "-" else path.read_bytes()
    policy = _policy_from_args(args)
    store = TrustStore.load(args.trust) if args.trust else TrustStore()

    auth_headers = []
    if args.auth_header:
        auth_headers = [args.auth_header]
    mail = MailContext(
        from_address=args.from_address or "",
        auth=parse_authentication_results(auth_headers),
        declared_method=args.method or "",
    )

    if raw.lstrip().lower().startswith(b"begin:vcalendar") or b"\nbegin:vcalendar" in raw.lower():
        result = process(raw, mail=mail, policy=policy, store=store, rewrite=False)
        payload = result.assessment.as_dict()
        payload["input"] = str(path)
        _emit(payload, as_json=args.json)
        return _exit_for(result.assessment.disposition)

    result = mime.process_message(raw, mail=mail, policy=policy, store=store)
    payload = result.summary()
    _emit(payload, as_json=args.json)
    if args.output:
        Path(args.output).write_bytes(mime.flatten(result))
    return _exit_for(result.worst)


def cmd_filter(args) -> int:
    raw = sys.stdin.buffer.read()
    policy = _policy_from_args(args)
    store = TrustStore.load(args.trust) if args.trust else TrustStore()

    auth_headers = []
    if args.auth_header:
        auth_headers = [args.auth_header]
    result = mime.process_message(
        raw,
        mail=MailContext(auth=parse_authentication_results(auth_headers)),
        policy=policy,
        store=store,
    )
    out = mime.flatten(result)
    sys.stdout.buffer.write(out)
    sys.stdout.buffer.flush()
    if args.verdict:
        with open(args.verdict, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(result.summary(), ensure_ascii=False) + "\n")
    if args.trust:
        store.save()
    return _exit_for(result.worst)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="invite-guard",
        description="Screen calendar invitations for meeting-link phishing.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(subparser):
        subparser.add_argument("--org-domain", help="comma-separated internal domains")
        subparser.add_argument("--org-name", help="organisation display name")
        subparser.add_argument("--trust", help="path to the JSON trust store")
        subparser.add_argument("--from-address", help="envelope From, for identity checks")
        subparser.add_argument("--auth-header", help="Authentication-Results header value")
        subparser.add_argument("--method", help="Content-Type method= parameter")
        subparser.add_argument("--json", action="store_true", help="machine-readable output")

    scan = sub.add_parser("scan", help="scan one .ics or .eml file")
    scan.add_argument("path", help="file path, or - for stdin")
    scan.add_argument("--output", help="write the rewritten message here")
    common(scan)
    scan.set_defaults(func=cmd_scan)

    filt = sub.add_parser("filter", help="stdin -> stdout mail filter")
    filt.add_argument("--verdict", help="append a JSON verdict line to this file")
    common(filt)
    filt.set_defaults(func=cmd_filter)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except OSError as exc:
        print(f"invite-guard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
