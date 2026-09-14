import re
from urllib.parse import urlparse


TARGET_BRANDS = {
    "PayPal": {
        "canonical": "paypal",
        "legit_domains": ["paypal.com"],
    },
    "Google": {
        "canonical": "google",
        "legit_domains": ["google.com"],
    },
    "Microsoft": {
        "canonical": "microsoft",
        "legit_domains": ["microsoft.com", "live.com", "office.com"],
    },
    "Apple": {
        "canonical": "apple",
        "legit_domains": ["apple.com", "icloud.com"],
    },
    "Amazon": {
        "canonical": "amazon",
        "legit_domains": ["amazon.com"],
    },
    "Facebook": {
        "canonical": "facebook",
        "legit_domains": ["facebook.com", "fb.com"],
    },
    "Instagram": {
        "canonical": "instagram",
        "legit_domains": ["instagram.com"],
    },
    "Netflix": {
        "canonical": "netflix",
        "legit_domains": ["netflix.com"],
    },
}

SUSPICIOUS_SUFFIXES = [
    "login",
    "verify",
    "secure",
    "account",
    "support",
    "update",
    "auth",
    "portal",
]

SUBSTITUTIONS = {
    "1": "l",
    "0": "o",
    "3": "e",
    "4": "a",
    "@": "a",
    "5": "s",
    "$": "s",
    "7": "t",
    "8": "b",
    "v": "u",
}

URGENT_KEYWORDS = [
    "urgent",
    "immediately",
    "suspended",
    "suspend",
    "verify",
    "verification",
    "action required",
    "account will be closed",
    "expires",
    "click now",
]

KNOWN_BRANDS = [
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
]


def detect_domain_similarity(domain_str: str):
    """
    Defensively detects domain similarity, brand impersonation, and typosquatting.
    Returns: (domain_similarity: bool, matched_brand: str | None, similarity_reason: str | None)
    """
    if not domain_str:
        return False, None, None

    domain = domain_str.strip().lower()

    # 1. Whitelist legitimate brand domains
    for brand_name, brand_info in TARGET_BRANDS.items():
        for legit in brand_info["legit_domains"]:
            if domain == legit or domain.endswith("." + legit):
                return False, None, None

    # 2. Extract candidate domain labels
    parts = domain.split(".")
    labels = []
    if len(parts) >= 2:
        labels.append(parts[-2])
        labels.append(parts[0])
    else:
        labels.append(domain)

    # De-duplicate while preserving order
    unique_labels = []
    for lbl in labels:
        if lbl and lbl not in unique_labels:
            unique_labels.append(lbl)

    # 3. Evaluate each label against target brands
    for label in unique_labels:
        # Detect suspicious suffixes (e.g. -login, -verify, etc.)
        detected_suffix = None
        core_label = label
        for sfx in SUSPICIOUS_SUFFIXES:
            pattern = rf"[-_.]{sfx}$|^{sfx}[-_.]|[-_.]{sfx}[-_.]|{sfx}$"
            if re.search(pattern, label):
                detected_suffix = sfx
                core_label = re.sub(pattern, "", label).strip("-_.")
                break

        tokens = [core_label] if detected_suffix and core_label else []
        if label not in tokens:
            tokens.append(label)

        for brand_name, brand_info in TARGET_BRANDS.items():
            canonical = brand_info["canonical"]

            for token in tokens:
                if not token:
                    continue

                # Case A: Exact brand token match
                if token == canonical:
                    reason = (
                        "Suspicious suffix"
                        if detected_suffix
                        else "Brand impersonation"
                    )
                    return True, brand_name, reason

                # Case B: Character substitution (e.g. 1 for l, 0 for o)
                if len(token) == len(canonical):
                    subbed = list(token)
                    has_sub = False
                    for i, ch in enumerate(subbed):
                        if ch in SUBSTITUTIONS and SUBSTITUTIONS[ch] == canonical[i]:
                            subbed[i] = canonical[i]
                            has_sub = True
                    if has_sub and "".join(subbed) == canonical:
                        reason = (
                            "Character substitution + suspicious suffix"
                            if detected_suffix
                            else "Character substitution"
                        )
                        return True, brand_name, reason

                # Case C: Extra character (insertion) e.g. paypaal -> paypal
                if len(token) == len(canonical) + 1:
                    for i in range(len(token)):
                        if token[:i] + token[i + 1 :] == canonical:
                            reason = (
                                "Extra character + suspicious suffix"
                                if detected_suffix
                                else "Extra character"
                            )
                            return True, brand_name, reason

                # Case D: Missing character (deletion) e.g. paypl -> paypal
                if len(token) == len(canonical) - 1:
                    for i in range(len(canonical)):
                        if canonical[:i] + canonical[i + 1 :] == token:
                            reason = (
                                "Missing character + suspicious suffix"
                                if detected_suffix
                                else "Missing character"
                            )
                            return True, brand_name, reason

    return False, None, None


def analyze_email(sender, subject, body, url):
    indicators = []
    evidence = []
    score = 0

    # -------------------------
    # 1. Sender analysis
    # -------------------------
    sender_match = re.match(r"^[^@\s]+@([^@\s]+)$", sender.strip())

    if not sender_match:
        score += 20
        indicators.append("Invalid sender email format")
        evidence.append("The sender address does not follow a normal email format.")
        domain = ""
    else:
        domain = sender_match.group(1).lower()

    # Pre-parse URL domain if URL is present
    url_domain = ""
    if url:
        try:
            url_domain = urlparse(url).netloc.lower()
        except Exception:
            url_domain = ""

    # -------------------------
    # 2. Suspicious domain terms
    # -------------------------
    suspicious_domain_terms = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "support",
    ]

    for term in suspicious_domain_terms:
        if term in domain:
            score += 10
            indicators.append("Suspicious domain pattern")
            evidence.append(
                f"The sender domain contains the suspicious term '{term}'."
            )
            break

    # -------------------------
    # 3. Brand impersonation & Domain similarity detection
    # -------------------------
    domain_sim_detected, matched_brand, similarity_reason = detect_domain_similarity(domain)

    # If sender domain was not flagged, check destination URL domain
    if not domain_sim_detected and url_domain:
        domain_sim_detected, matched_brand, similarity_reason = detect_domain_similarity(url_domain)

    if domain_sim_detected:
        score += 25
        indicators.append(f"Brand impersonation ({matched_brand})")
        evidence.append(
            f"The domain appears to imitate '{matched_brand}': {similarity_reason}."
        )
    else:
        # Fallback to general keyword search for known brands
        full_text = f"{sender} {subject} {body} {url}".lower()
        for brand in KNOWN_BRANDS:
            if brand in full_text:
                if brand in domain and not domain.endswith(f"{brand}.com"):
                    score += 20
                    indicators.append("Possible brand impersonation")
                    evidence.append(
                        f"The domain appears to imitate the brand '{brand}'."
                    )
                    domain_sim_detected = True
                    matched_brand = brand.capitalize()
                    similarity_reason = "Brand name in domain"
                    break

    # -------------------------
    # 4. Urgency / threat language
    # -------------------------
    full_text = f"{sender} {subject} {body} {url}".lower()
    found_keywords = []

    for keyword in URGENT_KEYWORDS:
        if keyword in full_text:
            found_keywords.append(keyword)

    if found_keywords:
        score += min(25, len(found_keywords) * 5)
        indicators.append("Urgency or threat language")
        evidence.append(
            "Suspicious urgency keywords detected: "
            + ", ".join(found_keywords)
        )

    # -------------------------
    # 5. URL analysis
    # -------------------------
    url_analysis = {
        "url": url,
        "scheme": "",
        "domain": "",
        "suspicious": False,
    }

    if url:
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            url_domain = parsed.netloc.lower()

            url_analysis["scheme"] = scheme
            url_analysis["domain"] = url_domain

            if scheme == "http":
                score += 15
                indicators.append("Insecure HTTP link")
                evidence.append(
                    "The message contains an HTTP link instead of HTTPS."
                )
                url_analysis["suspicious"] = True

            if "@" in url:
                score += 15
                indicators.append("Suspicious URL structure")
                evidence.append(
                    "The URL contains '@', which can be used to disguise the destination."
                )
                url_analysis["suspicious"] = True

        except Exception:
            score += 10
            indicators.append("Malformed URL")
            evidence.append("The supplied URL could not be parsed normally.")

    # -------------------------
    # 6. Long / complex domain
    # -------------------------
    if domain and len(domain) > 30:
        score += 5
        indicators.append("Unusually long domain")
        evidence.append("The sender domain is unusually long.")

    # -------------------------
    # Limit score strictly to 100
    # -------------------------
    score = min(score, 100)

    # -------------------------
    # Verdict
    # -------------------------
    if score >= 80:
        verdict = "CRITICAL"
    elif score >= 60:
        verdict = "HIGH"
    elif score >= 30:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    # -------------------------
    # Recommended action
    # -------------------------
    if score >= 60:
        recommended_action = (
            "Do not click links or reply to the message. "
            "Report it to your security team for investigation."
        )
    elif score >= 30:
        recommended_action = (
            "Treat the message with caution and verify the sender "
            "through a trusted channel."
        )
    else:
        recommended_action = (
            "No major phishing indicators were detected, "
            "but continue to verify unexpected messages."
        )

    domain_similarity = domain_sim_detected

    return {
        "risk_score": score,
        "verdict": verdict,
        "indicators": indicators,
        "evidence": evidence,
        "domain_analysis": {
            "sender_domain": domain,
            "suspicious": (
                any("domain" in indicator.lower() or "brand" in indicator.lower() for indicator in indicators)
                or domain_similarity
            ),
            "domain_similarity": domain_similarity,
            "matched_brand": matched_brand,
            "similarity_reason": similarity_reason,
        },
        "domain_similarity": domain_similarity,
        "matched_brand": matched_brand,
        "similarity_reason": similarity_reason,
        "url_analysis": url_analysis,
        "recommended_action": recommended_action,
    }