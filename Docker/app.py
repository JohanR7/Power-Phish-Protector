import os
import random
import base64
from flask import Flask, request, jsonify
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError, Error as PlaywrightError
import logging
import re # For regex operations (e.g., finding IPs in URL)
from urllib.parse import urlparse, urljoin # For URL manipulation
import tldextract # For domain extraction
import math # For entropy
from datetime import datetime
# from cryptography import x509 # For detailed SSL cert parsing (more complex)
# from cryptography.hazmat.backends import default_backend # For detailed SSL cert parsing
# import whois # For domain age - can be slow and unreliable
import requests # For some out-of-band checks if needed
from bs4 import BeautifulSoup # Optional, for HTML parsing if Playwright locators are not enough

app = Flask(__name__)

# --- Basic Logging ---
if not app.debug:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

# --- Configuration (Keep as is) ---
PROXY_SERVER = os.environ.get("PROXY_SERVER")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # ... more user agents
]

# --- Suspicious Words (Customize this list) ---
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "password",
    "banking", "financial", "paypal", "ebay", "amazon", "apple", "microsoft",
    "support", "alert", "confirm", "unlock", "restricted", "limited"
]

# --- Helper Functions ---
def calculate_entropy(text):
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def get_domain_age_and_ssl(url):
    """
    Placeholder for more complex domain age and SSL checks.
    WHOIS lookups can be slow and rate-limited.
    SSL checks with `requests` or `ssl` module can be done out-of-band.
    Playwright's `response.security_details()` provides some SSL info.
    """
    domain_info = {
        "domain_age_days": None,
        "ssl_valid": None, # True/False based on browser's assessment
        "hostname_matches_ssl_cert": None, # True/False
        "ssl_issuer": None,
        "ssl_certificate_expiry_days": None,
        "ssl_protocol": None, # e.g., TLS 1.3
        "ssl_subject_name": None,
    }
    # This is a simplified example. Real WHOIS and deep SSL analysis are complex.
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            return domain_info

        # Basic WHOIS (can be unreliable, often blocked, and slow)
        # try:
        #     domain_obj = whois.whois(hostname)
        #     if domain_obj.creation_date:
        #         creation_date = domain_obj.creation_date
        #         if isinstance(creation_date, list): creation_date = creation_date[0] # some TLDs return list
        #         if creation_date:
        #             domain_info["domain_age_days"] = (datetime.now() - creation_date).days
        # except Exception as e:
        #     app.logger.warning(f"WHOIS lookup failed for {hostname}: {e}")

        # SSL check using requests (simpler than full crypto parsing)
        # This happens OUTSIDE Playwright's context, so it's a separate request.
        # Playwright's response.security_details() is generally preferred if available and sufficient.
        try:
            # We will get this from Playwright response later, this is an alternative
            pass
        except requests.exceptions.SSLError as e:
            domain_info["ssl_valid"] = False
            app.logger.warning(f"SSL Error for {hostname} via requests: {e}")
        except Exception as e:
            app.logger.warning(f"Could not check SSL for {hostname} via requests: {e}")

    except Exception as e:
        app.logger.error(f"Error in get_domain_age_and_ssl for {url}: {e}")
    return domain_info


@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL not provided"}), 400

    url_to_scan = data['url']
    selected_user_agent = random.choice(USER_AGENTS)

    # Initialize results with all desired fields
    results = {
        "original_url": url_to_scan,
        "final_url": None,
        "status_code": None,
        "page_title": None,
        "screenshot_base64": None,
        "page_content_length": None,
        "number_of_links": 0,
        "number_of_external_links": 0,
        "number_of_forms": 0,
        "has_password_field": False,
        "has_input_fields": False, # More general than just password
        "has_iframes": False,
        "number_of_script_tags": 0, # Changed from has_script_tags to count
        "suspicious_words_found": [], # List of words found
        "number_of_redirects": 0, # Will be determined by Playwright's navigation history
        "url_contains_ip": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_to_scan)),
        "url_length": len(url_to_scan),
        "url_path_entropy": calculate_entropy(urlparse(url_to_scan).path), # Entropy of path part
        "url_query_entropy": calculate_entropy(urlparse(url_to_scan).query), # Entropy of query part
        "domain_info": { # Sub-dictionary for domain/SSL related info
            "domain_age_days": None,
            "ssl_valid": None,
            "hostname_matches_ssl_cert": None,
            "ssl_issuer": None,
            "ssl_certificate_expiry_days": None,
            "ssl_protocol": None,
            "ssl_subject_name": None,
        },
        "error": None
    }

    with sync_playwright() as p:
        browser = None
        context = None
        page_content = "" # To store page HTML for analysis
        all_responses = [] # To track redirects

        def handle_response(response):
            all_responses.append(response) # Store all responses to trace redirects

        try:
            browser_args = [
                '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas', '--no-first-run', '--no-zygote', '--disable-gpu'
            ]
            proxy_settings = {"server": PROXY_SERVER} if PROXY_SERVER else None
            if proxy_settings: app.logger.info(f"Using proxy: {PROXY_SERVER}")

            browser = p.chromium.launch(headless=True, args=browser_args, proxy=proxy_settings)
            context = browser.new_context(
                user_agent=selected_user_agent,
                ignore_https_errors=True, # Be cautious, but for scanning all sites...
                record_har_path=None # Could enable HAR for network details if needed
            )
            page = context.new_page()
            page.on("response", handle_response) # Register response handler for redirects

            app.logger.info(f"Scanning URL: {url_to_scan} with UA: {selected_user_agent}")

            # Navigate and get basic info
            # We use 'load' or 'networkidle' for more complete page state, but domcontentloaded is faster
            # For phishing, waiting longer might reveal more tricks.
            initial_response = page.goto(url_to_scan, timeout=90000, wait_until="networkidle") # Increased timeout, wait_until more comprehensive

            results["status_code"] = initial_response.status if initial_response else None
            results["final_url"] = page.url # This is the URL after all redirects

            # Calculate number of redirects
            # The first response in all_responses is the initial request's response.
            # If final_url is different from original_url, it's a redirect.
            # A more robust way: count distinct URLs in the redirect chain.
            redirect_chain = [resp.url for resp in all_responses if resp.request.is_navigation_request()]
            # Filter out non-redirects like subresource loads if any snuck in, though is_navigation_request helps
            unique_navigational_urls = []
            if redirect_chain:
                unique_navigational_urls.append(redirect_chain[0]) # Add first URL
                for i in range(1, len(redirect_chain)):
                    if redirect_chain[i] != redirect_chain[i-1]:
                         unique_navigational_urls.append(redirect_chain[i])
            results["number_of_redirects"] = max(0, len(unique_navigational_urls) -1)


            results["page_title"] = page.title()
            page_content = page.content() # Get full HTML content
            results["page_content_length"] = len(page_content)

            # SSL Information from Playwright's response
            if initial_response and initial_response.security_details():
                sec_details = initial_response.security_details()
                results["domain_info"]["ssl_valid"] = True # If details exist, browser considered it somewhat valid
                results["domain_info"]["ssl_issuer"] = sec_details.get("issuer")
                results["domain_info"]["ssl_protocol"] = sec_details.get("protocol")
                results["domain_info"]["ssl_subject_name"] = sec_details.get("subjectName")
                # Expiry: Playwright gives 'validFrom' and 'validTo' in seconds since epoch
                if sec_details.get("validTo"):
                    expiry_timestamp = sec_details.get("validTo")
                    expiry_date = datetime.fromtimestamp(expiry_timestamp)
                    results["domain_info"]["ssl_certificate_expiry_days"] = (expiry_date - datetime.now()).days
                # Hostname matching is implicitly handled by browser; if major mismatch, it would block/warn.
                # For a more explicit check, compare sec_details subject/SANs with page.url hostname.
                # This is a simplification:
                results["domain_info"]["hostname_matches_ssl_cert"] = True # Assume if page loaded over HTTPS with details.

            # Links
            links = page.locator('a[href]').all()
            results["number_of_links"] = len(links)
            current_domain = tldextract.extract(page.url).registered_domain
            external_links_count = 0
            for link_el in links:
                href = link_el.get_attribute('href')
                if href:
                    try:
                        # Ensure href is absolute for comparison
                        abs_href = urljoin(page.url, href)
                        link_domain = tldextract.extract(abs_href).registered_domain
                        if link_domain and link_domain != current_domain:
                            external_links_count += 1
                    except Exception:
                        pass # Invalid URL in href
            results["number_of_external_links"] = external_links_count

            # Forms and Input Fields
            forms = page.locator('form').all()
            results["number_of_forms"] = len(forms)
            if page.locator('input').count() > 0:
                results["has_input_fields"] = True
            if page.locator('input[type="password"]').count() > 0:
                results["has_password_field"] = True
            
            # iFrames
            if page.locator('iframe').count() > 0 or page.locator('frame').count() > 0: # include old 'frame' too
                results["has_iframes"] = True

            # Script Tags
            results["number_of_script_tags"] = page.locator('script').count()

            # Suspicious Words (scan visible text and some meta content)
            # For a more thorough check, parse `page_content` with BeautifulSoup
            # and check text nodes, meta tags, title, etc.
            # This is a simplified version checking visible text:
            body_text_lower = page.locator('body').text_content().lower()
            title_lower = results["page_title"].lower() if results["page_title"] else ""
            
            found_words = set()
            for word in SUSPICIOUS_KEYWORDS:
                if word in body_text_lower or word in title_lower:
                    found_words.add(word)
            # You could also check meta descriptions, etc.
            # meta_description = page.locator('meta[name="description"]').get_attribute('content')

            results["suspicious_words_found"] = list(found_words)


            # --- More advanced features (Domain Age, deeper SSL) would go into get_domain_age_and_ssl ---
            # --- or be called here if they need Playwright context.                       ---
            # --- For now, we rely on Playwright's response.security_details() for SSL    ---
            # --- Domain age via WHOIS is omitted for speed/reliability in this example. ---

            # Screenshot
            try:
                screenshot_bytes = page.screenshot(type="png", full_page=True, timeout=30000)
                results["screenshot_base64"] = base64.b64encode(screenshot_bytes).decode('utf-8')
            except Exception as e_ss:
                app.logger.warning(f"Could not take screenshot for {url_to_scan}: {e_ss}")
                results["error"] = results.get("error", "") + f" Screenshot failed: {str(e_ss)};"


            app.logger.info(f"Successfully scanned: {url_to_scan}")

        except PlaywrightTimeoutError as e:
            results["error"] = f"Timeout during Playwright operation: {str(e)}"
            app.logger.error(f"Playwright Timeout for {url_to_scan}: {e}")
        except PlaywrightError as e:
            results["error"] = f"Playwright error: {str(e)}"
            app.logger.error(f"Playwright Error for {url_to_scan}: {e}")
        except Exception as e:
            results["error"] = f"An unexpected error occurred: {str(e)}"
            app.logger.error(f"Unexpected Error for {url_to_scan}: {e}", exc_info=True)
        finally:
            if context:
                try: context.close()
                except Exception as e_ctx: app.logger.error(f"Error closing context: {e_ctx}")
            if browser:
                try: browser.close()
                except Exception as e_brw: app.logger.error(f"Error closing browser: {e_brw}")
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)