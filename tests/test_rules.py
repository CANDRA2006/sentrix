
import httpx
import pytest
import typer

from sentrix.cli import analyze_headers, validate_url


def test_missing_headers_are_reported():
    headers = httpx.Headers({})

    findings = analyze_headers(headers, is_https=True)

    assert len(findings) == 5
    assert all(item["status"] == "observed" for item in findings)


def test_present_headers_are_not_reported():
    headers = httpx.Headers({
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
    })

    findings = analyze_headers(headers, is_https=True)

    assert findings == []


def test_hsts_is_skipped_for_http():
    findings = analyze_headers(httpx.Headers({}), is_https=False)

    assert "HTTP-002" not in {item["id"] for item in findings}


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://localhost:3000",
    ],
)
def test_valid_urls(url):
    assert validate_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "not-a-url",
        "https://",
        "https://user:password@example.com",
    ],
)
def test_invalid_urls(url):
    with pytest.raises(typer.BadParameter):
        validate_url(url)
