import pytest

from phishguard.detector.url_parser import URLValidationError, is_private_or_reserved, parse_url


class TestAcceptsValidUrls:
    @pytest.mark.parametrize("url", ["http://example.com", "https://example.com/", "HTTPS://Example.COM/Path"])
    def test_http_and_https(self, url):
        parsed = parse_url(url)
        assert parsed.scheme in ("http", "https")
        assert parsed.host_ascii == "example.com"

    def test_original_preserved_separately_from_normalized(self):
        raw = "  HTTPS://User:Secret@WWW.Example.COM:443/a/B?x=1#frag  "
        parsed = parse_url(raw)
        assert parsed.original == raw
        assert parsed.normalized == "https://www.example.com/a/B?x=1"
        assert "Secret" not in parsed.normalized and "User" not in parsed.normalized
        assert parsed.has_fragment and parsed.fragment == "frag"

    def test_path_and_query_not_rewritten(self):
        parsed = parse_url("https://example.com/a%20b/../c?q=%2F&x=1")
        assert parsed.path == "/a%20b/../c"
        assert parsed.query == "q=%2F&x=1"

    def test_empty_path_normalized_to_slash(self):
        assert parse_url("https://example.com").normalized == "https://example.com/"

    def test_ports(self):
        parsed = parse_url("https://example.com:8443/x")
        assert parsed.port == 8443 and parsed.nonstandard_port
        assert parsed.normalized == "https://example.com:8443/x"
        default = parse_url("http://example.com:80/")
        assert not default.nonstandard_port and default.normalized == "http://example.com/"

    def test_ipv4(self):
        parsed = parse_url("http://192.0.2.10/login")
        assert parsed.host_type == "ipv4" and parsed.host_ascii == "192.0.2.10"
        assert not parsed.ip_obfuscated

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("http://3232235777/", "192.168.1.1"),  # decimal
            ("http://0xC0A80101/", "192.168.1.1"),  # hex
            ("http://0300.0250.01.01/", "192.168.1.1"),  # octal
            ("http://127.1/", "127.0.0.1"),  # shortened
        ],
    )
    def test_obfuscated_ipv4_resolved_like_a_browser(self, url, expected):
        parsed = parse_url(url)
        assert parsed.host_type == "ipv4"
        assert parsed.host_ascii == expected
        assert parsed.ip_obfuscated

    def test_ipv6(self):
        parsed = parse_url("https://[2001:DB8::1]:8443/path")
        assert parsed.host_type == "ipv6"
        assert parsed.host_ascii == "[2001:db8::1]"
        assert parsed.port == 8443

    def test_unicode_host_converted_to_punycode(self):
        parsed = parse_url("https://bücher.example/")
        assert parsed.host_ascii == "xn--bcher-kva.example"
        assert parsed.host_unicode == "bücher.example"
        assert parsed.is_idn

    def test_punycode_host_decoded_for_display(self):
        parsed = parse_url("https://xn--pypal-4ve.example/")
        assert parsed.host_unicode == "pаypal.example"  # Cyrillic а
        assert parsed.is_idn

    def test_credentials_detected_and_password_not_kept(self):
        parsed = parse_url("http://admin:hunter2@example.com/")
        assert parsed.has_credentials and parsed.username == "admin" and parsed.has_password
        assert "hunter2" not in repr(parsed)

    def test_at_sign_uses_last_at_as_delimiter(self):
        parsed = parse_url("http://paypal.com@evil.example/")
        assert parsed.host_ascii == "evil.example"
        assert parsed.username == "paypal.com"

    def test_percent_encoded_host_is_decoded_and_flagged(self):
        parsed = parse_url("http://%65xample.com/")
        assert parsed.host_ascii == "example.com"
        assert parsed.host_percent_encoded

    def test_trailing_dot_removed(self):
        parsed = parse_url("https://example.com./")
        assert parsed.host_ascii == "example.com" and parsed.had_trailing_dot

    def test_registrable_domain_with_multilabel_suffix(self):
        parsed = parse_url("https://a.b.example.co.uk/")
        assert parsed.registrable_domain == "example.co.uk"
        assert parsed.subdomain_labels == ("a", "b")

    def test_shared_hosting_tenant_is_its_own_domain(self):
        assert parse_url("https://victim.github.io/").registrable_domain == "victim.github.io"

    def test_localhost(self):
        parsed = parse_url("http://localhost:5000/")
        assert is_private_or_reserved(parsed)


class TestRejectsInvalidUrls:
    @pytest.mark.parametrize(
        ("value", "code"),
        [
            ("", "empty"),
            ("   ", "empty"),
            (None, "invalid_type"),
            (123, "invalid_type"),
            ("example.com", "missing_scheme"),
            ("example.com/login", "missing_scheme"),
            ("localhost:5000", "missing_scheme"),
            ("ftp://example.com/file", "unsupported_scheme"),
            ("javascript:alert(1)", "unsupported_scheme"),
            ("data:text/html,<script>alert(1)</script>", "unsupported_scheme"),
            ("file:///etc/passwd", "unsupported_scheme"),
            ("http:example.com", "malformed"),
            ("http://", "missing_host"),
            ("https:///path", "missing_host"),
            ("http://exa mple.com", "contains_whitespace"),
            ("http://example.com/\x00", "control_characters"),
            ("http://‮example.com", "invisible_characters"),
            ("http://999.1.1.1/", "invalid_ip"),
            ("http://1.2.3.4.5/", "invalid_ip"),
            ("http://256.256.256.256/", "invalid_ip"),
            ("http://example.123/", "invalid_hostname"),
            ("http://a..b.com/", "invalid_hostname"),
            ("http://-bad.example.com/", "invalid_hostname"),
            ("http://exa!mple.com/", "invalid_hostname"),
            ("http://example.c0m/", "invalid_tld"),
            ("http://intranet/", "not_fqdn"),
            ("http://[2001:db8::zz]/", "invalid_ipv6"),
            ("http://[2001:db8::1/", "invalid_ipv6"),
            ("http://2001:db8::1/", "invalid_host"),
            ("http://example.com:0/", "invalid_port"),
            ("http://example.com:99999/", "invalid_port"),
            ("http://example.com:abc/", "invalid_port"),
            ("http://evil.example\\@paypal.com/", "backslash_in_authority"),
            ("http://xn--zz.example/", "invalid_punycode"),
        ],
    )
    def test_rejections(self, value, code):
        with pytest.raises(URLValidationError) as exc:
            parse_url(value)
        assert exc.value.code == code
        assert exc.value.message  # always a user-facing explanation

    def test_max_length_is_configurable(self):
        url = "https://example.com/" + "a" * 100
        parse_url(url, max_length=200)
        with pytest.raises(URLValidationError) as exc:
            parse_url(url, max_length=50)
        assert exc.value.code == "too_long"

    def test_error_messages_never_echo_input(self):
        payload = "javascript:<script>alert(1)</script>"
        with pytest.raises(URLValidationError) as exc:
            parse_url(payload)
        assert "<script>" not in exc.value.message
