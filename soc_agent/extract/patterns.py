"""Regex candidate patterns + type validators. Spec: extraction-04-spec.md §7.2-7.4."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# --- TLD allowlist -----------------------------------------------------------------
# An allowlist, not a shape rule, is what keeps precision at 1.0 on the fixture corpus:
# "pskill.exe" and surname-shaped usernames like "j.okafor" are domain-shaped but must
# never be typed as domains. See extraction-04-spec.md §7.3.
_TLD_ALLOW: frozenset[str] = frozenset(
    {
        # generic
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "info",
        "biz",
        "name",
        "pro",
        # common new gTLDs
        "xyz",
        "top",
        "site",
        "online",
        "live",
        "club",
        "shop",
        "store",
        "cloud",
        "tech",
        "space",
        "website",
        "link",
        "click",
        "email",
        "host",
        "page",
        "news",
        "media",
        "group",
        "services",
        "solutions",
        "systems",
        "network",
        "digital",
        "agency",
        "world",
        "today",
        "life",
        "fun",
        # common ccTLDs
        "io",
        "co",
        "ai",
        "me",
        "tv",
        "cc",
        "uk",
        "de",
        "fr",
        "nl",
        "it",
        "es",
        "pl",
        "se",
        "no",
        "fi",
        "dk",
        "ch",
        "at",
        "be",
        "cz",
        "gr",
        "pt",
        "ie",
        "hu",
        "ro",
        "bg",
        "ua",
        "tr",
        "il",
        "ae",
        "sa",
        "eg",
        "za",
        "ng",
        "ke",
        "in",
        "pk",
        "bd",
        "jp",
        "kr",
        "tw",
        "hk",
        "sg",
        "my",
        "th",
        "vn",
        "id",
        "ph",
        "au",
        "nz",
        "ca",
        "mx",
        "br",
        "ar",
        "cl",
        "ru",
        "cn",
        # reserved
        "example",
        "test",
        "invalid",
        "localhost",
        "local",
        "onion",
        "arpa",
    }
)

# TLD/extension collision: `zip`, `mov`, `app`, `dev`, `sh` read as extensions, not TLDs;
# `com` stays a TLD (kept out of _FILE_EXT) — see extraction-04-spec.md §7.3.
_FILE_EXT: frozenset[str] = frozenset(
    {
        "exe",
        "dll",
        "sys",
        "ps1",
        "psm1",
        "bat",
        "cmd",
        "vbs",
        "js",
        "jse",
        "wsf",
        "hta",
        "scr",
        "lnk",
        "jar",
        "msi",
        "pif",
        "docx",
        "doc",
        "xlsx",
        "xls",
        "xlsm",
        "pptx",
        "ppt",
        "pdf",
        "rtf",
        "zip",
        "rar",
        "7z",
        "gz",
        "tar",
        "iso",
        "img",
        "dmg",
        "apk",
        "bin",
        "dat",
        "tmp",
        "log",
        "sh",
        "mov",
        "app",
    }
)

_TRAILING_PUNCT = ".,;:!?)\"'"

# --- candidate-generating patterns --------------------------------------------------

URL = re.compile(r"(?i)\b(https?|s?ftp|ftps|smb|ldaps?|file)://([^\s<>\"'`]+)")
EMAIL = re.compile(r"(?i)(?<![\w.+-])([\w.+-]{1,64})@([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?![\w-])")
IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
IPV6 = re.compile(
    r"(?<![\w:])((?=[0-9a-fA-F:]{2,45})[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:])"
)
HASH = re.compile(r"(?<![\w])([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![\w])")
DOMAIN = re.compile(
    r"(?i)(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-])"
)
_FILE_EXT_ALT = "|".join(sorted(_FILE_EXT, key=len, reverse=True))
# No spaces in the middle class: a filename never legitimately contains one in this
# corpus, and allowing them lets the match greedily swallow preceding prose words
# ("process pskill.exe" instead of "pskill.exe") — a real bug caught against fixture 04.
FILENAME = re.compile(r"(?i)(?<![\w/\\.])([\w][\w.-]{0,120}\.(?:" + _FILE_EXT_ALT + r"))(?![\w])")

_VERSION_PREFIX = re.compile(r"(?i)\bv(?:ersion)?\s*$")


def preceded_by_version_prefix(text: str, start: int) -> bool:
    """True if `text[:start]` ends in 'v'/'version' immediately before the match."""
    return bool(_VERSION_PREFIX.search(text[:start]))


# --- validators ----------------------------------------------------------------------
# Patterns are candidate generators; these validators are the arbiter (§7.4).


def validate_ip(value: str) -> str | None:
    """Return the canonical (.compressed) form, or None if invalid."""
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return None


def validate_domain(value: str) -> str | None:
    lowered = value.lower().rstrip(".")
    if not lowered or len(lowered) > 253:
        return None
    labels = lowered.split(".")
    if len(labels) < 2:
        return None
    if labels[-1] not in _TLD_ALLOW:
        return None
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return None
    return lowered


def validate_url(value: str) -> str | None:
    stripped = value.rstrip(_TRAILING_PUNCT)
    if not stripped:
        return None
    try:
        parsed = urlsplit(stripped)
    except ValueError:
        # A validator returns None for anything invalid — it never raises. Python's
        # urlsplit rejects some malformed netlocs (e.g. a stray, unbalanced "[") by
        # raising instead of just failing to parse.
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    return stripped


_HASH_TYPE_BY_LENGTH: dict[int, str] = {64: "hash_sha256", 40: "hash_sha1", 32: "hash_md5"}
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def validate_hash(value: str) -> tuple[str, str] | None:
    """Return (entity_type, lowercased value), or None if not a well-formed hash."""
    lowered = value.lower()
    hash_type = _HASH_TYPE_BY_LENGTH.get(len(lowered))
    if hash_type is None or not _HEX_RE.match(lowered):
        return None
    return hash_type, lowered


def validate_email(value: str) -> str | None:
    if value.count("@") != 1:
        return None
    local, _, domain = value.partition("@")
    if not local:
        return None
    canonical_domain = validate_domain(domain)
    if canonical_domain is None:
        return None
    return f"{local.lower()}@{canonical_domain}"


def validate_file_path(value: str) -> str | None:
    if "." not in value:
        return None
    ext = value.rsplit(".", 1)[-1].lower()
    if ext not in _FILE_EXT:
        return None
    return value
