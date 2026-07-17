"""
Tests for automation.config_validator — extended sanity checks over
automation.config.Config, beyond Config.validate()'s 4 required credentials.
"""

import unittest

from automation.config import Config
from automation.config_validator import validate_extended, _is_well_formed_url


class TestIsWellFormedUrl(unittest.TestCase):
    def test_accepts_https_url(self):
        self.assertTrue(_is_well_formed_url("https://blog.cyberdudebivash.in"))

    def test_accepts_http_url(self):
        self.assertTrue(_is_well_formed_url("http://example.com"))

    def test_rejects_empty_string(self):
        self.assertFalse(_is_well_formed_url(""))

    def test_rejects_scheme_only(self):
        self.assertFalse(_is_well_formed_url("https://"))

    def test_rejects_non_http_scheme(self):
        self.assertFalse(_is_well_formed_url("ftp://example.com"))

    def test_rejects_missing_scheme(self):
        self.assertFalse(_is_well_formed_url("blog.cyberdudebivash.in"))


class TestValidateExtended(unittest.TestCase):
    def test_default_config_passes(self):
        self.assertEqual(validate_extended(Config()), [])

    def test_zero_max_posts_per_run_is_flagged(self):
        cfg = Config()
        cfg.max_posts_per_run = 0
        issues = validate_extended(cfg)
        self.assertTrue(any("max_posts_per_run" in i for i in issues))

    def test_negative_retry_attempts_is_flagged(self):
        cfg = Config()
        cfg.retry_attempts = -1
        issues = validate_extended(cfg)
        self.assertTrue(any("retry_attempts" in i for i in issues))

    def test_zero_retry_base_delay_is_flagged(self):
        cfg = Config()
        cfg.retry_base_delay = 0
        issues = validate_extended(cfg)
        self.assertTrue(any("retry_base_delay" in i for i in issues))

    def test_malformed_url_field_is_flagged(self):
        cfg = Config()
        cfg.source_rss_url = "not-a-url"
        issues = validate_extended(cfg)
        self.assertTrue(any("source_rss_url" in i for i in issues))

    def test_zero_max_article_age_hours_is_flagged(self):
        cfg = Config()
        cfg.max_article_age_hours = 0
        issues = validate_extended(cfg)
        self.assertTrue(any("max_article_age_hours" in i for i in issues))

    def test_multiple_issues_all_reported(self):
        cfg = Config()
        cfg.max_posts_per_run = -5
        cfg.target_blog_url = "garbage"
        issues = validate_extended(cfg)
        self.assertGreaterEqual(len(issues), 2)


if __name__ == "__main__":
    unittest.main()
