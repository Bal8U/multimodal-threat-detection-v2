from url_detector.detector import extract_url_features

URL_FEATURE_NAMES = [
    "url_length", "hostname_length", "dot_count", "hyphen_count",
    "at_symbol", "uses_https", "has_ip", "digit_count",
    "suspicious_term_count", "path_length", "subdomain_count"
]

def url_feature_row(url: str):
    features = extract_url_features(url)
    return [[features[name] for name in URL_FEATURE_NAMES]]
