#!/usr/bin/env python3
"""Tests for Discord gate summary notifier."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent


def load_module():
    spec = importlib.util.spec_from_file_location(
        "notify_discord", REPO / "scripts" / "notify-discord.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


notify = load_module()


class NotifyDiscordTests(unittest.TestCase):
    def test_build_message_polished_layout(self):
        decision = {
            "gate_status": "FAILED",
            "blocked": True,
            "block_reasons": [
                "CRITICAL 등급 보안 이슈가 탐지되었습니다: PyYAML",
                "api_key=super-secret-value-should-not-leak",
            ],
        }
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_REPOSITORY": "KT-TECHUP-PROJECT5/web",
                "GITHUB_SHA": "abcdef1234567890",
                "GITHUB_RUN_ID": "123",
                "GITHUB_SERVER_URL": "https://github.com",
                "AI_REPORT_URL": "https://example.test/report",
            },
            clear=False,
        ):
            payload = notify.build_message(decision, profile="hard")

        self.assertEqual("**Hard mode 분석결과 FAILED**", payload["content"])
        embed = payload["embeds"][0]
        self.assertEqual("Hard mode · FAILED", embed["title"])
        self.assertIn("차단", embed["description"])
        self.assertEqual(0xED4245, embed["color"])
        self.assertIn("timestamp", embed)
        names = [field["name"] for field in embed["fields"] if field["name"] != "\u200b"]
        self.assertEqual(["레포지토리", "커밋", "차단사유", "필수 확인"], names)
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertIn("실행 로그", blob)
        self.assertIn("결과 리포트", blob)
        self.assertNotIn("AI 결과", blob)
        self.assertNotIn("GitHub Actions", blob)
        self.assertNotIn("super-secret-value-should-not-leak", blob)
        self.assertIn("[상세 내용 생략]", blob)

    def test_passed_uses_success_and_green(self):
        decision = {"gate_status": "PASSED", "blocked": False, "block_reasons": []}
        with mock.patch.dict(
            os.environ,
            {"GITHUB_REPOSITORY": "KT-TECHUP-PROJECT5/web", "GITHUB_SHA": "1234567"},
            clear=False,
        ):
            payload = notify.build_message(decision, profile="soft")
        embed = payload["embeds"][0]
        self.assertEqual("Soft mode · SUCCESS", embed["title"])
        self.assertEqual(0x57F287, embed["color"])
        self.assertIn("통과", embed["description"])

    def test_main_skips_without_webhook(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            decision_path = Path(temp_dir) / "gate-decision.json"
            decision_path.write_text(
                json.dumps(
                    {
                        "gate_status": "PASSED",
                        "blocked": False,
                        "block_reasons": [],
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"DISCORD_WEBHOOK_URL": ""}, clear=False):
                rc = notify.main(["--decision", str(decision_path), "--profile", "hard"])
            self.assertEqual(0, rc)


if __name__ == "__main__":
    unittest.main()
