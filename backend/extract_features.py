import re
import urllib.parse
import asyncio
import base64
import logging
import traceback
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from playwright.async_api import async_playwright, TimeoutError as PWTimeout

app = FastAPI(title="PhishOps Scanner Service")
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# ─── Request model ───────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    scan_id: str


# ─── Health check ────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


# ─── Scan endpoint ───────────────────────────────────────────────────────────

@app.post("/scan")
async def scan(req: ScanRequest):
    try:
        result = await asyncio.wait_for(
            run_scan(req.url, req.scan_id),
            timeout=60  # hard kill — malicious pages can hang forever
        )
        return result
    except asyncio.TimeoutError:
        logger.error(f"Scan timed out for {req.url}")
        raise HTTPException(status_code=504, detail="Scan timed out")
    except Exception as e:
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


# ─── Pure URL helpers ────────────────────────────────────────────────────────

def get_tld(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1].lower() if parts else ""


def is_ip(domain: str) -> int:
    return 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0


def char_continuation_rate(url: str) -> float:
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


# ─── Main async scan logic ───────────────────────────────────────────────────

async def run_scan(target_url: str, scan_id: str) -> dict:

    features = {k: 0 for k in [
        "URLLength", "DomainLength", "IsDomainIP",
        "CharContinuationRate", "URLCharProb", "TLDLength", "NoOfSubDomain",
        "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
        "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL",
        "DegitRatioInURL", "NoOfEqualsInURL", "NoOfQMarkInURL",
        "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL",
        "SpacialCharRatioInURL", "IsHTTPS", "HasTitle", "HasFavicon",
        "IsResponsive", "NoOfURLRedirect", "NoOfSelfRedirect",
        "HasDescription", "NoOfiFrame", "HasExternalFormSubmit",
        "HasSubmitButton", "HasHiddenFields", "HasPasswordField",
        "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef",
        "NoOfEmptyRef", "NoOfExternalRef",
    ]}

    features["URL"]    = ""
    features["Domain"] = ""
    features["TLD"]    = ""
    features["Title"]  = ""

    # Normalize URL
    parsed_check = urllib.parse.urlparse(target_url)
    netloc = parsed_check.netloc.lower()
    if not netloc.startswith("www."):
        target_url = target_url.replace(
            parsed_check.netloc, "www." + parsed_check.netloc, 1
        )

    # ── URL-only features ─────────────────────────────────────────────────
    domain        = target_url.replace("https://", "").replace("http://", "").split("/")[0]
    domain_length = len(domain)
    url_len       = domain_length + 7

    parts      = domain.split(".")
    tld        = parts[-1].lower()
    subdomains = max(0, len(parts) - 2)

    total_domain_letters = sum(c.isalpha() for c in domain)
    letters              = max(0, total_domain_letters - 4)
    letter_ratio         = round(letters / url_len, 3)

    digits      = sum(c.isdigit() for c in domain)
    digit_ratio = 0.0 if digits == 0 else round(digits / url_len, 3)

    total_special = sum(not c.isalnum() for c in domain)
    specials      = max(0, total_special - 1)
    special_ratio = round(specials / url_len, 3)

    has_obs, n_obs, obs_ratio = has_obfuscation(target_url)
    clean_domain = domain.replace("www.", "")

    features.update({
        "URL":                        target_url,
        "URLLength":                  url_len,
        "Domain":                     domain,
        "DomainLength":               domain_length,
        "IsDomainIP":                 is_ip(domain),
        "TLD":                        tld,
        "TLDLength":                  len(tld),
        "CharContinuationRate":       char_continuation_rate(domain),
        "URLCharProb":                url_char_prob(domain),
        "NoOfSubDomain":              subdomains,
        "HasObfuscation":             has_obs,
        "NoOfObfuscatedChar":         n_obs,
        "ObfuscationRatio":           obs_ratio,
        "NoOfLettersInURL":           letters,
        "LetterRatioInURL":           letter_ratio,
        "NoOfDegitsInURL":            digits,
        "DegitRatioInURL":            digit_ratio,
        "NoOfEqualsInURL":            target_url.count("="),
        "NoOfQMarkInURL":             target_url.count("?"),
        "NoOfAmpersandInURL":         target_url.count("&"),
        "NoOfOtherSpecialCharsInURL": specials,
        "SpacialCharRatioInURL":      special_ratio,
        "IsHTTPS":                    1 if target_url.lower().startswith("https://") else 0,
    })

    # ── Browser-based features ────────────────────────────────────────────
    screenshot_b64 = ""

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-notifications",       # block notification popups
                "--disable-geolocation",         # block location requests
                "--block-new-web-contents",      # block new windows/tabs
                "--disable-popup-blocking",      # let us catch popups explicitly
                "--autoplay-policy=user-gesture-required",
                "--disable-background-networking",
                "--disable-background-timer-throttling",
                "--disable-backgrounding-occluded-windows",
                "--disable-client-side-phishing-detection",
                "--disable-default-apps",
            ],
        )

        context = await browser.new_context(
            ignore_https_errors=True,  # needed for self-signed phishing certs
            java_script_enabled=True,  # keep JS — needed for feature extraction
            extra_http_headers={"DNT": "1"},
        )

        # Block dangerous / unnecessary resource types to reduce attack surface
        async def block_resources(route):
            if route.request.resource_type in ["font", "media", "websocket"]:
                await route.abort()
            else:
                await route.continue_()

        await context.route("**/*", block_resources)

        page = await context.new_page()

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
            await page.set_viewport_size({"width": 1280, "height": 720})
            await page.goto(target_url, wait_until="networkidle", timeout=20000)
        except PWTimeout:
            logger.warning(f"networkidle timeout for {target_url}, retrying with domcontentloaded")
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            except Exception as e:
                logger.warning(f"domcontentloaded also failed: {e}")
        except Exception as e:
            logger.warning(f"Page load error: {e}")
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            except Exception:
                pass

        # Screenshot → base64 (no disk writes, no shared volumes needed)
        try:
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshot_b64   = base64.b64encode(screenshot_bytes).decode()
        except Exception as e:
            logger.warning(f"Screenshot failed: {e}")

        # Title & basic meta
        try:
            title_el = await page.title()
            features["HasTitle"] = 1 if title_el.strip() else 0
            features["Title"]    = title_el.strip()
        except Exception:
            pass

        try:
            favicon = await page.query_selector('link[rel*="icon"]')
            features["HasFavicon"] = 1 if favicon else 0
        except Exception:
            pass

        try:
            viewport_meta = await page.query_selector('meta[name="viewport"]')
            features["IsResponsive"] = 1 if viewport_meta else 0
        except Exception:
            pass

        features["NoOfURLRedirect"]  = redirect_count
        features["NoOfSelfRedirect"] = self_redir_count

        try:
            desc = await page.query_selector('meta[name="description"]')
            features["HasDescription"] = 1 if desc else 0
        except Exception:
            pass

        # Wait for JS-injected elements
        try:
            await page.wait_for_timeout(2000)
        except Exception:
            pass

        try:
            iframe_count = await page.evaluate(
                "() => document.querySelectorAll('iframe, frame').length"
            )
            features["NoOfiFrame"] = iframe_count
        except Exception:
            pass

        try:
            forms    = await page.query_selector_all("form")
            ext_form = 0
            for form in forms:
                action = await form.get_attribute("action") or ""
                if action.startswith("http") and clean_domain not in action:
                    ext_form += 1
            features["HasExternalFormSubmit"] = 1 if ext_form > 0 else 0
        except Exception:
            pass

        try:
            submit_btn = await page.query_selector(
                'input[type="submit"], button[type="submit"]'
            )
            features["HasSubmitButton"] = 1 if submit_btn else 0
        except Exception:
            pass

        try:
            hidden_count = await page.evaluate(
                "() => document.querySelectorAll('input[type=\"hidden\"]').length"
            )
            features["HasHiddenFields"] = 1 if hidden_count > 0 else 0
        except Exception:
            pass

        try:
            pwd = await page.query_selector_all('input[type="password"]')
            features["HasPasswordField"] = 1 if len(pwd) > 0 else 0
        except Exception:
            pass

        try:
            features["NoOfImage"] = len(await page.query_selector_all("img"))
            features["NoOfCSS"]   = len(
                await page.query_selector_all('link[rel="stylesheet"]')
            )
            features["NoOfJS"] = len(await page.query_selector_all("script[src]"))
        except Exception:
            pass

        try:
            hrefs = await page.evaluate(
                "() => Array.from(document.querySelectorAll('a')).map(a => a.getAttribute('href') || '')"
            )
            base_dom = get_clean_domain(target_url)
            s_ref = e_ref = x_ref = 0
            for href in hrefs:
                href = href.strip()
                if not href:
                    e_ref += 1
                    continue
                href_lower = href.lower()
                if href_lower.startswith("javascript:") or href == "#":
                    s_ref += 1
                    continue
                if href_lower.startswith(("http://", "https://")):
                    if get_clean_domain(href) == base_dom:
                        s_ref += 1
                    else:
                        x_ref += 1
                else:
                    s_ref += 1

            features["NoOfSelfRef"]     = s_ref
            features["NoOfEmptyRef"]    = e_ref
            features["NoOfExternalRef"] = x_ref
        except Exception:
            pass

        await browser.close()

    return {
        **features,
        "screenshot_b64": screenshot_b64,
    }