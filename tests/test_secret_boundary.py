from __future__ import annotations

import unittest

from src.services.secret_boundary import sanitize_path, sanitize_text


class SecretBoundaryTests(unittest.TestCase):
    def test_known_credentials_are_redacted(self) -> None:
        value = (
            "AKIA1234567890ABCDEF ghp_" + "a" * 36
            + "\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
        )
        sanitized = sanitize_text(value)
        self.assertNotIn("AKIA1234567890ABCDEF", sanitized)
        self.assertNotIn("ghp_" + "a" * 36, sanitized)
        self.assertNotIn("BEGIN PRIVATE KEY", sanitized)

    def test_contextual_and_high_entropy_values_are_redacted(self) -> None:
        secret = "Qz7vN2mK8pL4xR9sT1wY6uI3oP0aS5dF"
        self.assertIn("[REDACTED", sanitize_text("api_token=" + secret))
        self.assertIn("[REDACTED", sanitize_text(secret))

    def test_prose_and_code_remain_usable(self) -> None:
        text = "Use a relative path such as infra/main.tf and set replicas = 3."
        self.assertEqual(sanitize_text(text), text)

    def test_control_input_and_paths_are_safe(self) -> None:
        self.assertNotIn("\x00", sanitize_path("infra/\x00main.tf"))
        self.assertNotIn("\x1b", sanitize_text("hello\x1b[31m"))


if __name__ == "__main__":
    unittest.main()
