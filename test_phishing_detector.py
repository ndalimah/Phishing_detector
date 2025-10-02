from phishing_detector import score_email, is_phishing


def test_obvious_phishing():
    text = (
        "Dear user,\n"
        "Your account has been suspended. Please verify your account and update your password now. "
        "Click here: http://192.0.2.1/login to confirm.\n"
    )
    score = score_email(text)
    assert score >= 0.5
    assert is_phishing(text, threshold=0.5)


def test_benign_email():
    text = (
        "Hi team,\n"
        "Please find the attached project plan. Let me know if you'd like to discuss in our next meeting.\n"
        "Thanks,\nAlice"
    )
    score = score_email(text)
    assert score < 0.5
    assert not is_phishing(text, threshold=0.5)


def test_html_mismatched_link():
    html = (
        "<html><body>" 
        "<p>Please <a href=\"http://malicious.example\">www.yourbank.com</a> to verify.</p>"
        "</body></html>"
    )
    score = score_email(html)
    assert score >= 0.5
    assert is_phishing(html, threshold=0.5)


def test_from_header_mismatch():
    text = (
        "Hello,\n"
        "Please verify at http://malicious.example/login\n"
    )
    # sender claims to be from example.com while link is malicious.example
    score_no_header = score_email(text)
    score_with_header = score_email(text, headers={"From": "alice@example.com"})
    assert score_with_header > score_no_header
    assert is_phishing(text, threshold=0.5, headers={"From": "alice@example.com"})


