"""Simple rule-based phishing email detector with a small CLI.

This module exposes:
- score_email(text, headers=None) -> float : returns a phishing score in [0, 1]
- is_phishing(text, threshold=0.5, headers=None) -> bool : returns True if score >= threshold

The implementation is intentionally small and rule-based so it runs without heavy setup.
"""
import re
from typing import List, Optional, Mapping

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None  # optional; requirements.txt includes it


PHISHING_KEYWORDS = [
    "account", "verify", "update", "password", "login", "bank", "secure", "urgent",
    "limited", "suspend", "confirm", "click", "link", "ssn", "social security",
]


def extract_urls(text: str) -> List[str]:
    # simple URL regex
    url_re = re.compile(r"https?://[\w\-./?=&%#]+", re.IGNORECASE)
    return url_re.findall(text)


def domain_from_url(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1).lower() if m else ""


def html_mismatched_links(html: str) -> bool:
    """Parse HTML and detect anchors where the visible text looks like a different domain than the href."""
    if BeautifulSoup is None:
        return False
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return False

    for a in soup.find_all("a"):
        href = a.get("href")
        if not href or not href.lower().startswith("http"):
            continue
        visible = (a.get_text() or "").strip().lower()
        href_domain = domain_from_url(href)
        # if visible text contains a domain-like token and it doesn't match href domain -> suspicious
        if "." in visible and href_domain and visible not in href_domain:
            return True
    return False


def has_mismatched_displayed_link(text: str) -> bool:
    # First try HTML-aware check
    if html_mismatched_links(text):
        return True

    # naive check: look for patterns like url in parentheses
    paren_urls = re.findall(r"\((https?://[^)]+)\)", text)
    for u in paren_urls:
        d = domain_from_url(u)
        if d and d not in text:
            return True
    # check for markdown style [text](url) where text contains a different domain
    md_links = re.findall(r"\[([^\]]+)\]\((https?://[^)]+)\)", text)
    for label, u in md_links:
        if "http" in label or ".com" in label or ".org" in label:
            d = domain_from_url(u)
            if d and label.lower() not in d:
                return True
    return False


def score_email(text: str, headers: Optional[Mapping[str, str]] = None) -> float:
    """Return a phishing score between 0 and 1.

    Heuristics used (weighted):
    - Keyword matches (0.3)
    - Number of URLs and presence of IP-based URLs (0.25)
    - Mismatched displayed link (0.25)
    - Presence of suspicious phrases like 'urgent' or 'confirm' (0.2)
    """
    text_lower = text.lower()

    # keywords
    kw_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in text_lower)
    kw_score = min(1.0, kw_hits / 6)  # normalize assuming ~6+ keywords -> 1

    # urls
    urls = extract_urls(text)
    url_count = len(urls)
    ip_url = any(re.search(r"https?://\d+\.\d+\.\d+\.\d+", u) for u in urls)
    url_score = min(1.0, url_count / 3 + (0.5 if ip_url else 0.0))

    # mismatched link
    mismatch = has_mismatched_displayed_link(text)
    mismatch_score = 1.0 if mismatch else 0.0

    # suspicious phrases
    suspicious_phrases = ["act now", "immediately", "click here", "wire transfer"]
    sp_hits = sum(1 for p in suspicious_phrases if p in text_lower)
    sp_score = min(1.0, sp_hits / 2)

    # header-based penalty
    header_penalty = 0.0
    if headers:
        # try common header keys
        from_header = headers.get("From") or headers.get("from") or headers.get("Sender")
        if from_header:
            # extract domain from From header if present
            m = re.search(r"@([A-Za-z0-9.-]+)", from_header)
            if m:
                sender_domain = m.group(1).lower()
                # if any link domains are very different from sender domain, add penalty
                link_domains = {domain_from_url(u) for u in urls}
                link_domains = {d for d in link_domains if d}
                if link_domains and not all(sender_domain in d or d in sender_domain for d in link_domains):
                    # stronger penalty when links are clearly different from sender domain
                    header_penalty = 0.40

    # weights (mismatch is most important for HTML/link mismatches)
    score = (
        0.30 * kw_score +
        0.25 * url_score +
        0.40 * mismatch_score +
        0.05 * sp_score
    )

    score = max(0.0, min(1.0, score + header_penalty))

    # clamp
    return max(0.0, min(1.0, score))


def is_phishing(text: str, threshold: float = 0.5, headers: Optional[Mapping[str, str]] = None) -> bool:
    return score_email(text, headers=headers) >= threshold


def cli():
    import argparse
    parser = argparse.ArgumentParser(description="Simple phishing email scorer")
    parser.add_argument("file", help="Path to a text file containing the email body or '-' for stdin")
    parser.add_argument("--from", dest="from_header", help="Optional From: header to provide sender address/domain")
    parser.add_argument("--threshold", type=float, default=0.5, help="Detection threshold (0-1)")
    args = parser.parse_args()

    if args.file == "-":
        import sys
        text = sys.stdin.read()
    else:
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()

    headers = {}
    if getattr(args, "from_header", None):
        headers["From"] = args.from_header

    score = score_email(text, headers=headers)
    print(f"phishing_score: {score:.3f}")
    print("phishing_guess:", "PHISHING" if score >= args.threshold else "LEGIT")


if __name__ == "__main__":
    cli()
