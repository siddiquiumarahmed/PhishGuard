import pytest

from phishguard.detector.url_features import (
    NUMERIC_FEATURE_NAMES,
    damerau_levenshtein_le1,
    extract_features,
    label_scripts,
    shannon_entropy,
    skeleton,
)
from phishguard.detector.url_parser import parse_url


def feats(url):
    return extract_features(parse_url(url))


def test_numeric_vector_has_fixed_keys_and_order():
    f = feats("https://www.example.com/a/b?c=1")
    assert tuple(f.numeric) == NUMERIC_FEATURE_NAMES
    assert all(isinstance(v, float) for v in f.numeric.values())


def test_basic_counts():
    f = feats("https://login-secure.sub.example.com:8443/a/b/c?x=1&y=2")
    n = f.numeric
    assert n["num_subdomains"] == 2
    assert n["nonstandard_port"] == 1.0
    assert n["num_query_params"] == 2
    assert n["path_depth"] == 3
    assert n["num_hyphens_host"] == 1
    assert n["is_https"] == 1.0


def test_ip_features():
    n = feats("http://3232235777/").numeric
    assert n["is_ip"] == 1.0 and n["ip_obfuscated"] == 1.0 and n["is_private_address"] == 1.0


def test_documentation_ip_is_not_treated_as_local():
    assert feats("http://203.0.113.7/").numeric["is_private_address"] == 0.0


def test_official_brand_domain_recognised_and_keywords_suppressed():
    f = feats("https://accounts.google.com/signin")
    assert "google" in f.official_brands
    assert f.keywords_host == []
    assert f.brand_mentions == []


def test_brand_in_subdomain_and_official_domain_spelled_out():
    f = feats("https://paypal.com.account-verify.example.net/signin")
    assert f.official_domain_in_subdomain == "paypal.com"
    assert any(m.location == "subdomain" and m.brand == "paypal" for m in f.brand_mentions)


def test_brand_with_affix_in_registered_domain():
    f = feats("https://paypalsecure.example/")
    assert any(m.location == "registrable" for m in f.brand_mentions)


def test_brand_substring_inside_ordinary_word_is_not_a_mention():
    # "pineapple" contains "apple"; "purchase" contains "chase".
    f = feats("https://pineapple-purchase.example/")
    assert f.brand_mentions == []


def test_short_alias_matched_only_as_whole_token():
    assert any(m.brand == "onlinesbi" for m in feats("https://sbi-kyc.example/").brand_mentions)
    assert feats("https://sbird.example/").brand_mentions == []


@pytest.mark.parametrize(
    ("url", "brand", "method"),
    [
        ("https://xn--pypal-4ve.example/", "paypal", "homoglyph"),
        ("https://paypa1.example/", "paypal", "ascii-substitution"),
        ("https://rnicrosoft.example/", "microsoft", "ascii-substitution"),
        ("https://netflx.example/", "netflix", "edit-distance"),
        ("https://amazno.example/", "amazon", "edit-distance"),
    ],
)
def test_lookalikes(url, brand, method):
    matches = feats(url).lookalikes
    assert any(m.brand == brand and m.method == method for m in matches), matches


def test_edit_distance_allowlist_avoids_common_words():
    assert feats("https://finance.example/").lookalikes == []  # 1 edit from "binance"
    assert feats("https://cloud.example/").lookalikes == []  # 1 edit from "icloud"


def test_mixed_script_detection():
    f = feats("https://xn--pypal-4ve.example/")
    assert f.mixed_script_labels and set(f.mixed_script_labels[0][1]) == {"CYRILLIC", "LATIN"}
    assert feats("https://bücher.example/").mixed_script_labels == []


def test_userinfo_domain():
    f = feats("http://www.paypal.com@203.0.113.7/")
    assert f.userinfo_domain == "www.paypal.com"
    assert any(m.location == "userinfo" for m in f.brand_mentions)


def test_redirect_and_download_and_encoding():
    f = feats("https://t.example/r?url=https%3A%2F%2Fevil.example%2F&x=%2541")
    assert f.redirect_params == ["url"]
    assert f.numeric["has_double_encoding"] == 1.0
    assert feats("https://dl.example/setup.exe").file_extension == "exe"
    assert feats("https://web.example/www.paypal.com").file_extension is None  # ".com" is not a file type


def test_shortener_and_free_hosting():
    assert feats("https://bit.ly/abc").shortener == "bit.ly"
    assert feats("https://x.github.io/").free_hosting_suffix == "github.io"


def test_helpers():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert skeleton("pаypal") == skeleton("paypal")  # Cyrillic а
    assert skeleton("paypa1") == skeleton("paypal")
    assert damerau_levenshtein_le1("paypal", "paypla")  # transposition
    assert damerau_levenshtein_le1("paypal", "paypall")
    assert not damerau_levenshtein_le1("paypal", "paypal")
    assert not damerau_levenshtein_le1("paypal", "pyapla")
    assert label_scripts("abc") == ["LATIN"]
