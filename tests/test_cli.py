"""CLI behaviour, especially the exit codes a gateway will act on."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from email.message import EmailMessage
from pathlib import Path

from invite_guard import cli

from .test_detection import SAMPLES
from .test_mime import build


class ExitCodes(unittest.TestCase):
    def test_attack_goes_to_review(self):
        with redirect_stdout(io.StringIO()):
            code = cli.main([
                "scan", str(SAMPLES / "attack" / "brand_subdomain_teams.ics"),
                "--from-address", "cfo@contoso-finance.com",
                "--auth-header", "spf=pass dkim=pass dmarc=pass",
            ])
        self.assertEqual(code, cli.EXIT_REVIEW)

    def test_benign_delivers(self):
        with redirect_stdout(io.StringIO()):
            code = cli.main([
                "scan", str(SAMPLES / "benign" / "zoom_external_client.ics"),
                "--from-address", "sarah.chen@acme-corp.com",
                "--auth-header", "spf=pass dkim=pass dmarc=pass",
            ])
        self.assertEqual(code, cli.EXIT_DELIVER)

    def test_internal_spoof_drops(self):
        with redirect_stdout(io.StringIO()):
            code = cli.main([
                "scan", str(SAMPLES / "attack" / "internal_spoof.ics"),
                "--from-address", "it-security@example.com",
                "--auth-header", "spf=fail dkim=fail dmarc=fail",
            ])
        self.assertEqual(code, cli.EXIT_DROP)

    def test_missing_file_is_usage_error(self):
        code = cli.main(["scan", "/nonexistent/file.ics"])
        self.assertEqual(code, 2)


class JsonOutput(unittest.TestCase):
    def test_json_roundtrip(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.main([
                "scan", str(SAMPLES / "attack" / "anchor_text_lie.ics"),
                "--json", "--from-address", "o@x.com",
                "--auth-header", "spf=pass dkim=pass dmarc=pass",
            ])
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["disposition"], "quarantine")
        self.assertTrue(payload["signals"])
        self.assertIn("links", payload)
        for signal in payload["signals"]:
            self.assertIn("code", signal)
            self.assertIn("detail", signal)


class FilterMode(unittest.TestCase):
    def test_filter_writes_verdict_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            verdict_path = Path(tmp) / "verdicts.jsonl"
            script = (
                "import sys; from invite_guard.cli import main;"
                f"sys.exit(main(['filter','--verdict','{verdict_path}',"
                "'--from-address','meetings@ms-teams-invite.com']))"
            )
            proc = subprocess.run(
                [sys.executable, "-c", script],
                input=build((SAMPLES / "attack" / "anchor_text_lie.ics").read_bytes()),
                capture_output=True,
            )
            self.assertEqual(proc.returncode, cli.EXIT_REVIEW)
            lines = verdict_path.read_text().strip().splitlines()
            self.assertEqual(len(lines), 1)
            verdict = json.loads(lines[0])
            self.assertEqual(verdict["worst_disposition"], "quarantine")

    def test_filter_passes_clean_message_bytes(self):
        raw = build((SAMPLES / "benign" / "google_meet_external.ics").read_bytes(),
                    from_addr='"Alex Kim" <alex.kim@northwind-traders.com>')
        script = (
            "import sys; from invite_guard.cli import main;"
            "sys.exit(main(['filter','--from-address','alex.kim@northwind-traders.com']))"
        )
        proc = subprocess.run([sys.executable, "-c", script], input=raw,
                              capture_output=True)
        self.assertEqual(proc.returncode, cli.EXIT_DELIVER)
        self.assertEqual(proc.stdout, raw)


class ParserSmoke(unittest.TestCase):
    def test_help(self):
        parser = cli.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--help"])


if __name__ == "__main__":
    unittest.main()
