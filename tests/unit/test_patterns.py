"""Pattern + validator tests. Spec: extraction-04-spec.md §16.2."""

from __future__ import annotations

from soc_agent.extract import patterns as p

# --- IPv4 ----------------------------------------------------------------------------


def test_ipv4_valid_forms() -> None:
    assert p.IPV4.findall("host 203.0.113.66 connected") == ["203.0.113.66"]
    assert p.validate_ip("203.0.113.66") == "203.0.113.66"


def test_ipv4_rejects_five_octets() -> None:
    assert p.IPV4.findall("1.2.3.4.5") == []


def test_ipv4_rejects_out_of_range_octet() -> None:
    assert p.validate_ip("10.0.19045.1") is None


def test_ipv4_version_prefix_guard() -> None:
    # "v1.2.3.4" fails the pattern's own lookbehind (no space between v and digits).
    assert p.IPV4.findall("v1.2.3.4") == []
    # "version 1.2.3.4" matches the pattern but must be dropped by the explicit guard.
    text = "upgraded to version 1.2.3.4 today"
    m = p.IPV4.search(text)
    assert m is not None
    assert p.preceded_by_version_prefix(text, m.start()) is True


def test_ipv4_accepts_documented_residual_risk() -> None:
    # A four-part version number that isn't prefixed by v/version is indistinguishable
    # from an IPv4 address by any local rule — accepted and documented (§7.4).
    assert p.validate_ip("10.0.22.41") == "10.0.22.41"
    text = "os build 10.0.22.41 shipped"
    m = p.IPV4.search(text)
    assert m is not None
    assert p.preceded_by_version_prefix(text, m.start()) is False


# --- IPv6 ----------------------------------------------------------------------------


def test_ipv6_valid_forms() -> None:
    assert p.IPV6.findall("addr 2001:db8::1 seen") == ["2001:db8::1"]
    assert p.IPV6.findall("loop ::1 back") == ["::1"]
    assert p.validate_ip("2001:db8::1") == "2001:db8::1"


def test_ipv6_rejects_cef_header_and_bare_hex() -> None:
    assert p.IPV6.findall("CEF:0|Vendor") == []
    assert p.IPV6.findall("deadbeef") == []


# --- Hashes ----------------------------------------------------------------------------


def test_hash_lengths_map_to_types() -> None:
    assert p.validate_hash("a" * 32) == ("hash_md5", "a" * 32)
    assert p.validate_hash("a" * 40) == ("hash_sha1", "a" * 40)
    assert p.validate_hash("a" * 64) == ("hash_sha256", "a" * 64)


def test_hash_rejects_wrong_lengths() -> None:
    assert p.validate_hash("a" * 63) is None
    assert p.validate_hash("a" * 65) is None


def test_hash_rejects_non_hex_base64_blob() -> None:
    # fixture 10's captured command line — must never be typed as a hash.
    assert p.validate_hash("SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0") is None


def test_hash_lowercases() -> None:
    upper = "A" * 64
    assert p.validate_hash(upper) == ("hash_sha256", "a" * 64)


# --- Domains -----------------------------------------------------------------------


def test_domain_valid() -> None:
    assert p.validate_domain("example-billing.net") == "example-billing.net"
    assert p.validate_domain("payroll-update.example-billing.net") is not None


def test_domain_rejects_process_and_usernames() -> None:
    """The precision regression guard: typing by TLD shape instead of allowlist
    creates false positives on the fixture corpus. Any implementation typing the
    TLD by shape (e.g. 2+ alphabetic chars) instead of an allowlist fails here."""
    for value in ["pskill.exe", "j.okafor", "t.baros", "m.silva", "d.chen", "s.novak"]:
        assert p.validate_domain(value) is None, value


def test_domain_rejects_overlong_name() -> None:
    long_label = "a" * 64
    assert p.validate_domain(f"{long_label}.com") is None
    overlong = ".".join(["a" * 50] * 6) + ".com"
    assert len(overlong) > 253
    assert p.validate_domain(overlong) is None


def test_extension_tld_collision() -> None:
    assert p.validate_file_path("payload.zip") == "payload.zip"
    assert p.validate_domain("payload.zip") is None
    assert p.validate_domain("example.com") == "example.com"
    assert p.validate_file_path("example.com") is None


# --- URLs ----------------------------------------------------------------------------


def test_url_schemes() -> None:
    assert p.URL.findall("sftp://transfer.example-cloudshare.net/upload")
    assert p.URL.findall("smb://host/share")
    assert p.URL.findall("https://payroll-update.example-billing.net/login")


def test_url_trailing_punctuation_stripped() -> None:
    assert p.validate_url("https://evil.example.com/x.") == "https://evil.example.com/x"
    assert p.validate_url("https://evil.example.com/x)") == "https://evil.example.com/x"


def test_url_never_raises_on_malformed_bracket_netloc() -> None:
    """A validator returns None for anything invalid — it never raises. Caught via
    the LLM assist: the model is instructed to copy indicators verbatim, defanged
    form included, so an un-refanged "evil[.]com"-style netloc must not crash
    urlsplit's strict IPv6-bracket check (Python 3.14)."""
    assert p.validate_url("https://payroll-update[.]example-billing[.]net/login") is None


def test_url_requires_scheme_and_host() -> None:
    assert p.validate_url("file://") is None


# --- Email -----------------------------------------------------------------------


def test_email_match_and_validate() -> None:
    assert p.EMAIL.findall("mail a@evil.example.com now") == [("a", "evil.example.com")]
    assert p.validate_email("a@evil.example.com") == "a@evil.example.com"


def test_email_rejects_bad_domain() -> None:
    assert p.validate_email("a@pskill.exe") is None


# --- Masking (order of application; enforced by regex_pass, sanity-checked here) ----


def test_masking_prevents_double_counting() -> None:
    text = "visit https://evil.example.com/x and mail a@evil.example.com"
    urls = p.URL.findall(text)
    emails = p.EMAIL.findall(text)
    assert len(urls) == 1
    assert len(emails) == 1
