import re
#import math
import urllib.parse
import json
import sys
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

# ─── pure URL helpers ───────────────────────────────────────────────────────

def get_tld(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1].lower() if parts else ""

def is_ip(domain: str) -> int:
    return 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0

def char_continuation_rate(url: str) -> float:
    """
    Dataset definition: ratio of consecutive pairs where both chars are
    alphanumeric OR both are non-alphanumeric (punctuation/structural).
    Dots, slashes, hyphens all count as the same 'other' class,
    so www.domain.com/ (mostly letters+dots) scores close to 1.0.
    """
    if len(url) < 2:
        return 0.0

    def char_class(c):
        return 'alnum' if c.isalnum() else 'other'

    same = sum(
        1 for i in range(1, len(url))
        if char_class(url[i]) == char_class(url[i - 1])
    )
    return round(same / (len(url) - 1), 4)

def url_char_prob(url: str) -> float:
    """
    FIX 3: Dataset definition — average per-character probability,
    i.e. 1 / number_of_unique_characters  (not Shannon entropy).
    """
    unique = set(url)
    if not unique:
        return 0.0
    return round(1 / len(unique), 6)

def has_obfuscation(url: str):
    url_lower         = url.lower()
    percent_encodings = re.findall(r'%[0-9a-f]{2}', url_lower)
    hex_patterns      = re.findall(r'0x[0-9a-f]+', url_lower)
    punycode          = re.findall(r'xn--[a-z0-9-]+', url_lower)
    at_symbol         = url_lower.count('@')

    total_count = (
        len(percent_encodings) + len(hex_patterns) +
        len(punycode) + at_symbol
    )
    has   = 1 if total_count > 0 else 0
    ratio = round(total_count / max(len(url), 1), 4)
    return has, total_count, ratio

def get_clean_domain(url: str) -> str:
    return urlparse(url).netloc.replace("www.", "").lower()


# ─── main extractor ────────────────────────────────────────────────────────

def extract_features(target_url: str) -> dict:

    features = {k: 0 for k in [
        "URLLength", "DomainLength", "IsDomainIP",
        "CharContinuationRate", "URLCharProb", "TLDLength", "NoOfSubDomain",
        "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
        "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL",
        "DegitRatioInURL", "NoOfEqualsInURL", "NoOfQMarkInURL",
        "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL",
        "SpacialCharRatioInURL", "IsHTTPS", "HasTitle", "HasFavicon", "IsResponsive",
        "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription",
        "NoOfiFrame", "HasExternalFormSubmit", "HasSubmitButton",
        "HasHiddenFields", "HasPasswordField", "NoOfImage", "NoOfCSS",
        "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
    ]}

    features["URL"]    = ""
    features["Domain"] = ""
    features["TLD"]    = ""
    features["Title"]  = ""
    # Normalize URL: add www. if not present after scheme
    parsed_check = urllib.parse.urlparse(target_url)
    netloc = parsed_check.netloc.lower()
    if not netloc.startswith("www."):
        target_url = target_url.replace(parsed_check.netloc, "www." + parsed_check.netloc, 1)

    # ── URL-only features — PhiUSIIL exact formulas ───────────────────────
    domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]

    # ── URL-only features — PhiUSIIL exact formulas ───────────────────────
    # Extract domain: strip scheme, take the host part (keeps www.)
    domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]
    domain_length = len(domain)

    # URLLength: domain_length + 7 (dataset-verified formula)
    url_len = domain_length + 7

    # TLD and subdomains
    parts      = domain.split(".")
    tld        = parts[-1].lower()
    subdomains = max(0, len(parts) - 2)

    # Letters: total alpha chars in domain minus 4
    total_domain_letters = sum(c.isalpha() for c in domain)
    letters              = max(0, total_domain_letters - 4)
    letter_ratio         = round(letters / url_len, 3)

    # Digits: counted directly from domain
    digits      = sum(c.isdigit() for c in domain)
    digit_ratio = 0.0 if digits == 0 else round(digits / url_len, 3)

    # Special chars: non-alphanumeric chars in domain minus 1
    total_special = sum(not c.isalnum() for c in domain)
    specials      = max(0, total_special - 1)
    special_ratio = round(specials / url_len, 3)

    # Obfuscation — still computed from full URL
    has_obs, n_obs, obs_ratio = has_obfuscation(target_url)

    # Clean domain without www — used only for link comparison in browser section
    clean_domain = domain.replace("www.", "")

    features["URL"]                        = target_url
    features["URLLength"]                  = url_len
    features["Domain"]                     = domain
    features["DomainLength"]               = domain_length
    features["IsDomainIP"]                 = is_ip(domain)
    features["TLD"]                        = tld
    features["TLDLength"]                  = len(tld)
    features["CharContinuationRate"]       = char_continuation_rate(domain)
    features["URLCharProb"]                = url_char_prob(domain)
    features["NoOfSubDomain"]              = subdomains
    features["HasObfuscation"]             = has_obs
    features["NoOfObfuscatedChar"]         = n_obs
    features["ObfuscationRatio"]           = obs_ratio
    features["NoOfLettersInURL"]           = letters
    features["LetterRatioInURL"]           = letter_ratio
    features["NoOfDegitsInURL"]            = digits
    features["DegitRatioInURL"]            = digit_ratio
    features["NoOfEqualsInURL"]            = target_url.count("=")
    features["NoOfQMarkInURL"]             = target_url.count("?")
    features["NoOfAmpersandInURL"]         = target_url.count("&")
    features["NoOfOtherSpecialCharsInURL"] = specials
    features["SpacialCharRatioInURL"]      = special_ratio
    features["IsHTTPS"]                    = 1 if target_url.lower().startswith("https://") else 0

    # ── Browser-based features ─────────────────────────────────────────────
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu",
                  "--disable-dev-shm-usage", "--disable-extensions"],
        )
        page = browser.new_page()

        redirect_count   = 0
        self_redir_count = 0
        base_nav_domain  = get_clean_domain(target_url)

        def on_response(response):
            nonlocal redirect_count, self_redir_count
            try:
                if (response.request.is_navigation_request()
                        and response.status in (301, 302, 303, 307, 308)):
                    redirect_count += 1
                    if get_clean_domain(response.url) == base_nav_domain:
                        self_redir_count += 1
            except Exception:
                pass

        page.on("response", on_response)

        try:
            # Set a fixed viewport so screenshots look consistent
            page.set_viewport_size({"width": 1280, "height": 720})
            page.goto(target_url, wait_until="networkidle", timeout=20000)
            
            page.screenshot(path="/app/output/screenshot.png")
        except Exception:
            try:
                page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            except Exception:
                browser.close()
                return features

        title_el = page.title()
        features["HasTitle"]  = 1 if title_el.strip() else 0
        features["Title"]     = title_el.strip()

        favicon = page.query_selector('link[rel*="icon"]')
        features["HasFavicon"] = 1 if favicon else 0

        viewport_meta = page.query_selector('meta[name="viewport"]')
        features["IsResponsive"] = 1 if viewport_meta else 0

        features["NoOfURLRedirect"]  = redirect_count
        features["NoOfSelfRedirect"] = self_redir_count

        desc = page.query_selector('meta[name="description"]')
        features["HasDescription"] = 1 if desc else 0

        # Wait extra for JS-injected elements (iframes, hidden fields)
        try:
            page.wait_for_timeout(2000)
        except Exception:
            pass

        # Count both <iframe> and <frame> including JS-injected ones
        iframe_count = page.evaluate(
            "() => document.querySelectorAll('iframe, frame').length"
        )
        features["NoOfiFrame"] = iframe_count

        forms    = page.query_selector_all("form")
        ext_form = 0
        for form in forms:
            action = form.get_attribute("action") or ""
            if action.startswith("http") and clean_domain not in action:
                ext_form += 1
        features["HasExternalFormSubmit"] = 1 if ext_form > 0 else 0

        submit_btn = page.query_selector('input[type="submit"], button[type="submit"]')
        features["HasSubmitButton"] = 1 if submit_btn else 0

        # Use evaluate to catch JS-injected hidden inputs
        hidden_count = page.evaluate(
            "() => document.querySelectorAll('input[type=\"hidden\"]').length"
        )
        features["HasHiddenFields"] = 1 if hidden_count > 0 else 0

        pwd = page.query_selector_all('input[type="password"]')
        features["HasPasswordField"] = 1 if len(pwd) > 0 else 0

        features["NoOfImage"] = len(page.query_selector_all("img"))
        features["NoOfCSS"]   = len(page.query_selector_all('link[rel="stylesheet"]'))
        features["NoOfJS"]    = len(page.query_selector_all("script[src]"))

        def classify_links(page_obj, base_url: str):
            base_dom = get_clean_domain(base_url)

            hrefs = page_obj.evaluate(
                "() => Array.from(document.querySelectorAll('a')).map(a => a.getAttribute('href') || '')"
            )

            s_ref, e_ref, x_ref = 0, 0, 0
            for href in hrefs:
                href = href.strip()

                # Only truly blank href="" counts as empty
                if not href:
                    e_ref += 1
                    continue

                href_lower = href.lower()

                # javascript: and # are self-refs
                if href_lower.startswith("javascript:") or href == "#":
                    s_ref += 1
                    continue

                if href_lower.startswith("http://") or href_lower.startswith("https://"):
                    link_dom = get_clean_domain(href)
                    if link_dom == base_dom:
                        s_ref += 1
                    else:
                        x_ref += 1
                else:
                    # Relative paths, anchors like #section → self-ref
                    s_ref += 1

            return s_ref, e_ref, x_ref

        self_ref, empty_ref, ext_ref = classify_links(page, target_url)
        features["NoOfSelfRef"]     = self_ref
        features["NoOfEmptyRef"]    = empty_ref
        features["NoOfExternalRef"] = ext_ref
        browser.close()

    return features

if __name__ == "__main__":
    # Check if a URL was passed as an argument
    if len(sys.argv) > 1:
        url_to_scan = sys.argv[1]
        try:
            # Run your extraction function
            results = extract_features(url_to_scan)
            # Print the results as JSON so main.py can read them
            print(json.dumps(results))
        except Exception as e:
            # If it fails, return an error JSON
            print(json.dumps({"error": str(e)}))