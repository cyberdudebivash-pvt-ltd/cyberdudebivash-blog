#!/usr/bin/env python3
"""
Generate search-index.json for CYBERDUDEBIVASH SENTINEL APEX blog.
Scans all posts/*.html and extracts title, slug, date, description, and type.
"""

import os
import json
import re
from html.parser import HTMLParser
from datetime import datetime

POSTS_DIR = "/home/user/cyberdudebivash-blog/posts"
OUTPUT_FILE = "/home/user/cyberdudebivash-blog/search-index.json"
TITLE_SUFFIX = " | CYBERDUDEBIVASH SENTINEL APEX"
TITLE_SUFFIX2 = "| CYBERDUDEBIVASH SENTINEL APEX"
DESC_MAX = 120


class PostParser(HTMLParser):
    """Parse a post HTML file to extract metadata."""

    def __init__(self):
        super().__init__()
        self.title = ""
        self.description = ""
        self.date_published = ""
        self.badges = []  # list of (class, text)

        self._in_title = False
        self._title_buf = []
        self._capture_badge = False
        self._badge_class = ""
        self._badge_buf = []
        self._in_script_json_ld = False
        self._json_ld_buf = []
        self._script_type = ""

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        if tag == "title":
            self._in_title = True
            self._title_buf = []

        elif tag == "meta":
            name = attr_dict.get("name", "").lower()
            prop = attr_dict.get("property", "").lower()
            content = attr_dict.get("content", "")
            if name == "description" and content and not self.description:
                self.description = content

        elif tag == "script":
            stype = attr_dict.get("type", "")
            if stype == "application/ld+json":
                self._in_script_json_ld = True
                self._json_ld_buf = []
            self._script_type = stype

        elif tag == "span":
            cls = attr_dict.get("class", "")
            if "badge" in cls and any(
                c in cls
                for c in ["bdg-cisa", "bdg-red", "bdg-purple", "bdg-cyan"]
            ):
                self._capture_badge = True
                self._badge_class = cls
                self._badge_buf = []

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
            raw = "".join(self._title_buf).strip()
            # Strip suffix
            for suffix in [TITLE_SUFFIX, TITLE_SUFFIX2]:
                if raw.endswith(suffix):
                    raw = raw[: -len(suffix)].strip()
                    break
            self.title = raw

        elif tag == "script":
            if self._in_script_json_ld:
                self._in_script_json_ld = False
                raw_json = "".join(self._json_ld_buf)
                try:
                    data = json.loads(raw_json)
                    # Could be a list or object
                    items = data if isinstance(data, list) else [data]
                    for item in items:
                        if isinstance(item, dict):
                            dp = item.get("datePublished", "")
                            if dp and not self.date_published:
                                self.date_published = dp[:10]  # YYYY-MM-DD
                except Exception:
                    pass
            self._script_type = ""

        elif tag == "span":
            if self._capture_badge:
                self._capture_badge = False
                text = "".join(self._badge_buf).strip()
                if text:
                    self.badges.append((self._badge_class, text))

    def handle_data(self, data):
        if self._in_title:
            self._title_buf.append(data)
        elif self._in_script_json_ld:
            self._json_ld_buf.append(data)
        elif self._capture_badge:
            self._badge_buf.append(data)


def clean_text(text):
    """Remove emoji and extra whitespace from badge text."""
    # Remove common emoji ranges
    emoji_pattern = re.compile(
        "[\U0001F600-\U0001F64F"
        "\U0001F300-\U0001F5FF"
        "\U0001F680-\U0001F6FF"
        "\U0001F700-\U0001F77F"
        "\U0001F780-\U0001F7FF"
        "\U0001F800-\U0001F8FF"
        "\U0001F900-\U0001F9FF"
        "\U0001FA00-\U0001FA6F"
        "\U0001FA70-\U0001FAFF"
        "☀-⛿"
        "✀-➿"
        "]+",
        flags=re.UNICODE,
    )
    text = emoji_pattern.sub("", text)
    return text.strip()


def infer_type(badges):
    """Determine post type from badge classes and text."""
    # Priority order: more specific first
    for cls, text in badges:
        text_clean = clean_text(text).upper()

        # CISA badges -> ADVISORY
        if "bdg-cisa" in cls:
            if "KEV" in text_clean:
                return "ADVISORY"
            return "ADVISORY"

        # Purple badges -> RANSOMWARE
        if "bdg-purple" in cls:
            if "RANSOMWARE" in text_clean or "MALWARE" in text_clean:
                return "RANSOMWARE"
            return "RANSOMWARE"

    # Check cyan badges for content type
    for cls, text in badges:
        text_clean = clean_text(text).upper()
        if "bdg-cyan" in cls:
            if "CVE" in text_clean or "ZERO-DAY" in text_clean or "ZERO DAY" in text_clean:
                if "ZERO" in text_clean:
                    return "ZERO-DAY"
                return "CVE"
            if "RANSOMWARE" in text_clean:
                return "RANSOMWARE"
            if "AI" in text_clean:
                return "AI SECURITY"
            if "ADVISORY" in text_clean:
                return "ADVISORY"
            if "MALWARE" in text_clean:
                return "INTEL"
            if "BREACH" in text_clean:
                return "INTEL"
            if "INTEL" in text_clean:
                return "INTEL"
            if "THREAT" in text_clean:
                return "INTEL"
            if "ACTOR" in text_clean:
                return "INTEL"

    # Check red badges for CVE/ZERO-DAY
    for cls, text in badges:
        text_clean = clean_text(text).upper()
        if "bdg-red" in cls:
            if "ZERO-DAY" in text_clean or "ZERO DAY" in text_clean:
                return "ZERO-DAY"
            if "CVE" in text_clean:
                return "CVE"
            # CVSS scores indicate CVE
            if "CVSS" in text_clean:
                return "CVE"
            if "EXPLOITED" in text_clean:
                return "CVE"

    return "INTEL"


def format_date(dt):
    return dt.strftime("%Y-%m-%d")


def process_posts():
    entries = []
    files = sorted(os.listdir(POSTS_DIR))
    html_files = [f for f in files if f.endswith(".html")]
    total = len(html_files)
    print(f"Found {total} HTML files in {POSTS_DIR}")

    errors = 0
    for i, filename in enumerate(html_files):
        if i % 200 == 0:
            print(f"  Processing {i}/{total}...")

        filepath = os.path.join(POSTS_DIR, filename)
        slug = filename[:-5]  # strip .html

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            print(f"  ERROR reading {filename}: {e}")
            errors += 1
            continue

        parser = PostParser()
        try:
            parser.feed(content)
        except Exception as e:
            print(f"  WARN parsing {filename}: {e}")
            # Continue with partial data

        title = parser.title or slug.replace("-", " ").title()
        description = parser.description or ""
        date_str = parser.date_published

        # Fallback: try regex on datePublished in JSON-LD
        if not date_str:
            m = re.search(r'"datePublished"\s*:\s*"([0-9]{4}-[0-9]{2}-[0-9]{2})', content)
            if m:
                date_str = m.group(1)

        # Fallback: file modification time
        if not date_str:
            mtime = os.path.getmtime(filepath)
            date_str = format_date(datetime.fromtimestamp(mtime))

        # Truncate description
        desc_truncated = description[:DESC_MAX].rstrip()
        if len(description) > DESC_MAX:
            # Try to cut at last space
            last_space = desc_truncated.rfind(" ")
            if last_space > DESC_MAX - 30:
                desc_truncated = desc_truncated[:last_space]
            desc_truncated += "…"

        post_type = infer_type(parser.badges)

        entries.append(
            {
                "t": title,
                "s": slug,
                "d": date_str,
                "desc": desc_truncated,
                "tp": post_type,
            }
        )

    if errors:
        print(f"  {errors} files had read errors")

    return entries


def main():
    print("Generating search-index.json...")
    entries = process_posts()

    print(f"\nTotal entries: {len(entries)}")

    # Sort by date descending (newest first)
    entries.sort(key=lambda x: x["d"], reverse=True)

    output_path = OUTPUT_FILE
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, separators=(",", ":"))

    size = os.path.getsize(output_path)
    print(f"Written to: {output_path}")
    print(f"File size: {size:,} bytes ({size / 1024:.1f} KB)")

    # Verify
    print("\nVerification:")
    with open(output_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"  Valid JSON: YES")
    print(f"  Entry count: {len(data)}")

    # Sample output
    print("\nSample entries (first 3):")
    for entry in data[:3]:
        print(f"  {entry}")

    print("\nType distribution:")
    from collections import Counter
    types = Counter(e["tp"] for e in data)
    for tp, count in types.most_common():
        print(f"  {tp}: {count}")


if __name__ == "__main__":
    main()
