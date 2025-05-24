#!/usr/bin/env python3
"""
Flask Backend for Phishing Detection Extension
Handles email content and URL analysis requests from Chrome extension
"""
import os
import requests
import json
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0' # Suppress oneDNN optimization messages
os.environ['TRANSFORMERS_CACHE'] = './model_cache' # Set cache directory for models
PLAYWRIGHT_SCANNER_URL = os.environ.get("PLAYWRIGHT_SCANNER_URL", "http://localhost:5000/scan")
PLAYWRIGHT_SCANNER_TIMEOUT_SECONDS = 120 # Timeout for the call to the scanner, adjust as needed
from transformers import pipeline
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
# import json # already imported
import urllib.parse
import re
import torch # Explicitly import torch

app = Flask(__name__)
CORS(app, origins=["chrome-extension://*"], allow_headers=["Content-Type"], methods=["GET", "POST", "OPTIONS"])

# Trusted domains whitelist
TRUSTED_DOMAINS = {
    # Google services
    'google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'googledrive.com',
    'docs.google.com', 'accounts.google.com', 'myaccount.google.com',
    # Microsoft services
    'microsoft.com', 'outlook.com', 'live.com', 'hotmail.com', 'office.com',
    'teams.microsoft.com', 'onedrive.live.com',
    # Major platforms
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
    'amazon.com', 'apple.com', 'netflix.com', 'spotify.com',
    # Banks
    'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
    # Other trusted services
    'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org'
}

# Trusted email patterns
TRUSTED_EMAIL_PATTERNS = [
    r'.*@google\.com$', r'.*@youtube\.com$', r'.*@microsoft\.com$',
    r'.*@outlook\.com$', r'.*@amazon\.com$', r'.*@paypal\.com$',
    r'.*@github\.com$', r'noreply@.*\.google\.com$',
    r'no-reply@.*\.microsoft\.com$'
]

# --- Model Loading ---
url_classification_pipeline = None
email_content_pipeline = None

print("Initializing Phishing Detection Models...")

# 1. Load URL Classification Model
try:
    print("Loading URL classification model (ealvaradob/bert-finetuned-phishing)...")
    url_classification_pipeline = pipeline(
        "text-classification",
        model="ealvaradob/bert-finetuned-phishing",
        device=-1,  # -1 for CPU, 0 for GPU 0
        framework="pt"
    )
    print("URL classification model loaded successfully!")
except Exception as e:
    print(f"Error loading URL classification model: {e}")

# 2. Load Email Content Classification Model
try:
    print("Loading Email content classification model (ElSlay/BERT-Phishing-Email-Model)...")
    email_content_pipeline = pipeline(
        "text-classification",
        model="ElSlay/BERT-Phishing-Email-Model",
        device=-1,  # -1 for CPU, 0 for GPU 0
        framework="pt"
    )
    print("Email content classification model loaded successfully!")
except Exception as e:
    print(f"Error loading Email content classification model: {e}")

analysis_stats = {
    'emails_analyzed': 0,
    'urls_analyzed': 0,
    'threats_detected': 0,
    'false_positives_prevented': 0,
    'email_model_predictions': {'phishing': 0, 'safe': 0, 'error': 0},
    'url_model_predictions': {'phishing': 0, 'safe': 0, 'error': 0},
    'playwright_scans_performed': 0,
    'playwright_scan_errors': 0
}

def is_trusted_domain(url_or_email):
    try:
        if '@' in url_or_email:
            domain = url_or_email.split('@')[1].lower()
        else:
            parsed_url = url_or_email if url_or_email.startswith(('http://', 'https://')) else f'http://{url_or_email}'
            domain = urllib.parse.urlparse(parsed_url).netloc.lower()
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith('.' + trusted):
                return True, trusted
        return False, None
    except Exception:
        return False, None

def is_trusted_email_pattern(email):
    if not email: return False
    email_lower = email.lower()
    for pattern in TRUSTED_EMAIL_PATTERNS:
        if re.match(pattern, email_lower):
            return True
    return False

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy', 'timestamp': datetime.now().isoformat(),
        'service': 'phishing-detection-backend',
        'url_model_loaded': url_classification_pipeline is not None,
        'email_model_loaded': email_content_pipeline is not None
    })

@app.route('/analyze-email', methods=['POST'])
def analyze_email_route():
    try:
        email_data = request.get_json()
        if not email_data:
            return jsonify({'error': 'No email data provided'}), 400
        
        print_email_request_summary(email_data)
        analysis_result = perform_email_analysis(email_data)
        
        analysis_stats['emails_analyzed'] += 1
        if analysis_result.get('risk_level') in ['high', 'critical']:
            analysis_stats['threats_detected'] += 1
        
        print_analysis_result_summary(analysis_result)
        return jsonify(analysis_result)
    except Exception as e:
        print(f"Error in /analyze-email route: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'status': 'error'}), 500

@app.route('/analyze-url', methods=['POST'])
def analyze_url_route():
    try:
        url_data = request.get_json()
        if not url_data or not url_data.get('url'):
            return jsonify({'error': 'No URL provided'}), 400
        
        url_to_analyze = url_data['url']
        print(f"\n{'='*20} URL ANALYSIS REQUEST {'='*20}")
        print(f"Timestamp: {datetime.now().isoformat()}\nURL: {url_to_analyze}")
        
        analysis_result = perform_url_analysis(url_to_analyze) # ML analysis
        
        # Always fetch playwright scan details for direct URL analysis, unless ML already said it's whitelisted
        playwright_scan_data = None
        if not analysis_result.get('is_trusted_domain'):
            playwright_scan_data = fetch_playwright_scan_details(url_to_analyze)
            analysis_stats['playwright_scans_performed'] += 1
            if playwright_scan_data.get("error"):
                 analysis_stats['playwright_scan_errors'] += 1
        
        analysis_result['playwright_scan_details'] = playwright_scan_data # Add playwright results
        
        analysis_stats['urls_analyzed'] += 1 # This counts ML analysis primarily
        if analysis_result.get('risk_level') in ['high', 'critical']:
            analysis_stats['threats_detected'] += 1
            
        print("ANALYSIS RESULT (including Playwright if applicable):")
        print(json.dumps(analysis_result, indent=2))
        print(f"{'='*50}\n")
        return jsonify(analysis_result)
    except Exception as e:
        print(f"Error in /analyze-url route: {str(e)}")
        return jsonify({'error': 'Internal server error', 'status': 'error'}), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify({'stats': analysis_stats, 'timestamp': datetime.now().isoformat()})

def print_email_request_summary(email_data):
    print(f"\n{'='*20} EMAIL ANALYSIS REQUEST {'='*20}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Platform: {email_data.get('platform', 'unknown')}")
    print(f"Subject: {email_data.get('subject', 'N/A')}")
    print(f"Sender: {email_data.get('sender', 'N/A')}")
    print(f"Content Length: {len(email_data.get('content', ''))}")
    print(f"URLs Found: {len(email_data.get('urls', []))}")

def print_analysis_result_summary(result):
    print("ANALYSIS RESULT:")
    print(json.dumps(result, indent=2))
    print(f"{'='*60}\n")

def perform_email_analysis(email_data):
    subject = email_data.get('subject', '')
    sender_email_address = email_data.get('sender', '')
    content = email_data.get('content', '')
    urls_in_email = email_data.get('urls', [])

    risk_score = 0
    risk_factors = []
    trust_factors = []
    ml_email_content_details = {}
    analyzed_url_details = []

    is_trusted_sender, trusted_sender_domain = False, None
    if sender_email_address:
        is_trusted_sender, trusted_sender_domain = is_trusted_domain(sender_email_address)
        if not is_trusted_sender:
            is_trusted_sender = is_trusted_email_pattern(sender_email_address)
    
    if is_trusted_sender:
        risk_score -= 50
        trust_factors.append(f"Sender ({sender_email_address}) is trusted (domain/pattern: {trusted_sender_domain or 'matched pattern'})")
        print(f"TRUSTED SENDER: {sender_email_address}")
    else:
        if sender_email_address:
             risk_factors.append(f"Sender ({sender_email_address}) is not on trusted lists.")
        else:
             risk_factors.append("Sender email address not provided or empty.")

    if email_content_pipeline and (subject or content):
        text_for_email_model = f"Subject: {subject}\n\nBody:\n{content}"
        try:
            print(f"Analyzing email content with BERT (ElSlay). Length: {len(text_for_email_model)}")
            prediction = email_content_pipeline(text_for_email_model, truncation=True, max_length=512)[0]
            pred_label = prediction['label']
            pred_score = prediction['score']
            ml_email_content_details = {'model_prediction': pred_label, 'confidence': pred_score}
            is_phishing_email_pred = 'phishing' in pred_label.lower() or pred_label == 'LABEL_1'

            if is_phishing_email_pred:
                analysis_stats['email_model_predictions']['phishing'] += 1
                email_ml_risk_contribution = 0
                if pred_score > 0.9: email_ml_risk_contribution = 40
                elif pred_score > 0.7: email_ml_risk_contribution = 25
                elif pred_score > 0.5: email_ml_risk_contribution = 15
                
                if not is_trusted_sender:
                    risk_score += email_ml_risk_contribution
                else:
                    risk_score += email_ml_risk_contribution * 0.25
                    risk_factors.append(f"Email Content ML: Predicted '{pred_label}' ({pred_score:.2f}) - reduced impact due to trusted sender")
                if email_ml_risk_contribution > 0 and not is_trusted_sender:
                     risk_factors.append(f"Email Content ML: Predicted '{pred_label}' with confidence {pred_score:.2f}")
            else:
                analysis_stats['email_model_predictions']['safe'] += 1
                if pred_score > 0.8:
                    risk_score -= 15
                    trust_factors.append(f"Email Content ML: Predicted '{pred_label}' with high confidence {pred_score:.2f}")
        except Exception as e:
            print(f"Error during Email Content ML analysis: {e}")
            risk_factors.append(f"Email Content ML analysis failed: {str(e)}")
            ml_email_content_details = {'error': str(e)}
            analysis_stats['email_model_predictions']['error'] += 1
    elif not email_content_pipeline:
        risk_factors.append("Email content ML model not loaded.")

    heuristic_weight_multiplier = 0.25 if is_trusted_sender else 1.0
    if ml_email_content_details.get('model_prediction', '').lower() == 'phishing email' and ml_email_content_details.get('confidence', 0) > 0.8:
        heuristic_weight_multiplier *= 0.5

    suspicious_subject_keywords = ['urgent', 'immediate', 'verify', 'suspend', 'expire', 'warning', 'action required', 'limited time', 'prize']
    for keyword in suspicious_subject_keywords:
        if keyword in subject.lower():
            risk_score += int(10 * heuristic_weight_multiplier)
            risk_factors.append(f"Suspicious keyword in subject: '{keyword}' (weight: {heuristic_weight_multiplier:.2f})")

    urgency_keywords_content = ['urgent', 'immediately', 'expires soon', 'account suspended', 'locked', 'verify now', 'within 24 hours', 'security alert']
    for keyword in urgency_keywords_content:
        if keyword in content.lower():
            risk_score += int(8 * heuristic_weight_multiplier)
            risk_factors.append(f"Urgency indicator in content: '{keyword}' (weight: {heuristic_weight_multiplier:.2f})")

    trusted_url_count = 0
    if urls_in_email:
        for url_info in urls_in_email:
            url_text = url_info.get('url', '')
            if not url_text: continue

            is_url_trusted, url_trusted_domain = is_trusted_domain(url_text)
            playwright_scan_for_this_url = None # Initialize

            if is_url_trusted:
                trusted_url_count += 1
                trust_factors.append(f"URL links to trusted domain: {url_trusted_domain} ({url_text[:70]}...)")
                analyzed_url_details.append({
                    'url': url_text, 
                    'status': 'trusted', 
                    'trusted_domain': url_trusted_domain,
                    'playwright_scan': None # No scan for trusted
                })
            else:
                shortener_found = False
                suspicious_shorteners = ['bit.ly', 'tinyurl', 'short.link', 'tiny.cc', 'is.gd', 'soo.gd', 't.co']
                for pattern in suspicious_shorteners:
                    if pattern in url_text.lower():
                        risk_score += int(15 * heuristic_weight_multiplier)
                        risk_factors.append(f"Suspicious URL shortener: {pattern} in {url_text[:70]}... (weight: {heuristic_weight_multiplier:.2f})")
                        shortener_found = True
                        # Scan shorteners with Playwright as they hide the final destination
                        playwright_scan_for_this_url = fetch_playwright_scan_details(url_text)
                        analysis_stats['playwright_scans_performed'] += 1
                        if playwright_scan_for_this_url.get("error"):
                             analysis_stats['playwright_scan_errors'] += 1

                        analyzed_url_details.append({
                            'url': url_text, 
                            'status': 'shortener', 
                            'pattern': pattern,
                            'playwright_scan': playwright_scan_for_this_url
                        })
                        break
                
                if not shortener_found:
                    url_ml_analysis_result = perform_url_analysis(url_text) # ML analysis
                    
                    # Perform Playwright scan for non-trusted, non-shortener URLs
                    playwright_scan_for_this_url = fetch_playwright_scan_details(url_text)
                    analysis_stats['playwright_scans_performed'] += 1
                    if playwright_scan_for_this_url.get("error"):
                         analysis_stats['playwright_scan_errors'] += 1

                    analyzed_url_details.append({
                        'url': url_text,
                        'status': 'ml_analyzed',
                        'ml_risk_level': url_ml_analysis_result.get('risk_level'),
                        'ml_score': url_ml_analysis_result.get('risk_score'),
                        'ml_label': url_ml_analysis_result.get('model_label'),
                        'playwright_scan': playwright_scan_for_this_url # Add playwright results here
                    })

                    if url_ml_analysis_result.get('risk_level') == 'critical':
                        risk_score += 35 if not is_trusted_sender else 10
                        risk_factors.append(f"URL ML: Critical risk URL detected: {url_text[:70]}... (Score: {url_ml_analysis_result.get('risk_score')})")
                    elif url_ml_analysis_result.get('risk_level') == 'high':
                        risk_score += 20 if not is_trusted_sender else 5
                        risk_factors.append(f"URL ML: High risk URL detected: {url_text[:70]}... (Score: {url_ml_analysis_result.get('risk_score')})")
                    elif url_ml_analysis_result.get('risk_level') == 'medium':
                        risk_score += 10 if not is_trusted_sender else 2
                        risk_factors.append(f"URL ML: Medium risk URL detected: {url_text[:70]}... (Score: {url_ml_analysis_result.get('risk_score')})")
        
        if trusted_url_count > 0 and len(urls_in_email) > 0:
            trust_ratio = trusted_url_count / len(urls_in_email)
            if trust_ratio >= 0.8:
                risk_score -= 20
                trust_factors.append(f"High ratio of trusted URLs: {trusted_url_count}/{len(urls_in_email)}")
            elif trust_ratio < 0.3 and len(urls_in_email) > 2 :
                risk_score += 10
                risk_factors.append(f"Low ratio of trusted URLs: {trusted_url_count}/{len(urls_in_email)}")

    final_risk_score = max(0, risk_score)
    risk_level = 'safe'
    status_message = 'Analysis complete.'

    if is_trusted_sender:
        if final_risk_score >= 70: risk_level, status_message = 'critical', 'Trusted sender, but very high risk factors detected in content/URLs.'
        elif final_risk_score >= 50: risk_level, status_message = 'high', 'Trusted sender, but significant suspicious elements found.'
        elif final_risk_score >= 30: risk_level, status_message = 'medium', 'Trusted sender, but some concerning elements noted.'
        elif final_risk_score >= 10: risk_level, status_message = 'low', 'Trusted sender, minor concerns, likely safe.'
        else:
            risk_level, status_message = 'safe', 'Trusted sender, appears safe.'
            if not risk_factors: analysis_stats['false_positives_prevented'] += 1
    else:
        if final_risk_score >= 80: risk_level, status_message = 'critical', 'Critical phishing risk detected!'
        elif final_risk_score >= 50: risk_level, status_message = 'high', 'High phishing risk detected.'
        elif final_risk_score >= 25: risk_level, status_message = 'medium', 'Suspicious content or URLs found.'
        elif final_risk_score >= 10: risk_level, status_message = 'low', 'Minor suspicious indicators noted.'
        else: risk_level, status_message = 'safe', 'No significant threats detected.'
        
    return {
        'status': status_message,
        'risk_level': risk_level,
        'risk_score': final_risk_score,
        'risk_factors': risk_factors,
        'trust_factors': trust_factors,
        'is_trusted_sender': is_trusted_sender,
        'sender_analysis': {'address': sender_email_address, 'is_trusted': is_trusted_sender, 'trusted_source': trusted_sender_domain},
        'email_content_ml_analysis': ml_email_content_details,
        'url_analysis_summary': {
            'total_urls': len(urls_in_email),
            'trusted_urls_count': trusted_url_count,
            'analyzed_url_details': analyzed_url_details
        },
        'analysis_timestamp': datetime.now().isoformat()
    }

def perform_url_analysis(url_to_analyze):
    """Perform phishing analysis on individual URL using bert-finetuned-phishing.
       This function now PRIMARILY handles the ML model classification.
       Playwright scan is called separately by the routes or perform_email_analysis.
    """
    try:
        is_trusted, trusted_domain = is_trusted_domain(url_to_analyze)
        if is_trusted:
            print(f"TRUSTED DOMAIN (URL ML Analysis): {url_to_analyze} -> {trusted_domain}")
            analysis_stats['false_positives_prevented'] += 1
            return {
                'status': f'URL from trusted domain: {trusted_domain}', 'risk_level': 'safe', 'risk_score': 0,
                'risk_factors': [], 'trust_factors': [f'Domain {trusted_domain} is whitelisted'],
                'is_trusted_domain': True, 'trusted_domain': trusted_domain,
                'url': url_to_analyze, 'ml_prediction': False, 'confidence': 1.0, 'model_label': 'TRUSTED_WHITELIST'
            }

        if url_classification_pipeline is None:
            analysis_stats['url_model_predictions']['error'] += 1
            return {
                'status': 'URL ML Model not available', 'risk_level': 'unknown', 'risk_score': 0,
                'risk_factors': ['URL ML model failed to load'], 'url': url_to_analyze
            }

        print(f"Analyzing URL with BERT (ealvaradob): {url_to_analyze}")
        prediction_result = url_classification_pipeline(url_to_analyze, truncation=True, max_length=512)[0]
        label = prediction_result['label']
        confidence = prediction_result['score']
        
        is_phishing_pred = label.upper() == 'PHISHING'
        risk_level, status_msg, risk_score_val = 'unknown', 'Analysis error', 0

        if is_phishing_pred:
            analysis_stats['url_model_predictions']['phishing'] += 1
            if confidence > 0.95: risk_level, status_msg, risk_score_val = 'critical', 'ML: Critical phishing URL (very high conf)', int(confidence * 100)
            elif confidence > 0.80: risk_level, status_msg, risk_score_val = 'high', 'ML: Likely phishing URL (high conf)', int(confidence * 100)
            elif confidence > 0.60: risk_level, status_msg, risk_score_val = 'medium', 'ML: Potentially suspicious URL (med conf)', int(confidence * 80)
            else: risk_level, status_msg, risk_score_val = 'low', 'ML: Low confidence phishing prediction', int(confidence * 50)
        else:
            analysis_stats['url_model_predictions']['safe'] += 1
            if confidence > 0.9: risk_level, status_msg, risk_score_val = 'safe', 'ML: URL appears safe (high conf)', 0
            elif confidence > 0.7: risk_level, status_msg, risk_score_val = 'safe', 'ML: URL likely safe (med conf)', 0
            else: risk_level, status_msg, risk_score_val = 'low', 'ML: URL likely safe (low conf legitimate)', 5
        
        return {
            'status': status_msg, 'risk_level': risk_level, 'risk_score': risk_score_val,
            'risk_factors': [f'URL ML Prediction: {label} (Confidence: {confidence:.2f})'] if is_phishing_pred and confidence > 0.6 else [],
            'trust_factors': [f'URL ML Prediction: {label} (Confidence: {confidence:.2f})'] if not is_phishing_pred and confidence > 0.7 else [],
            'is_trusted_domain': False, 'url': url_to_analyze,
            'ml_prediction': is_phishing_pred, 'confidence': float(confidence), 'model_label': label,
            'analysis_timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Error in URL ML analysis for '{url_to_analyze}': {e}")
        analysis_stats['url_model_predictions']['error'] += 1
        import traceback
        traceback.print_exc()
        return {
            'status': 'URL ML analysis error', 'risk_level': 'unknown', 'risk_score': 0,
            'risk_factors': [f'URL ML analysis failed: {str(e)}'], 'url': url_to_analyze
        }
    
def fetch_playwright_scan_details(url_to_scan):
    """
    Calls the Dockerized Playwright service to perform a deep scan on the URL.
    Returns the JSON response from the scanner service, with defaults for expected fields.
    """
    print(f"Calling Playwright scanner for deep analysis of URL: {url_to_scan}")
    playwright_results = {"url_submitted_for_scan": url_to_scan} # Original key, good for reference

    try:
        scanner_payload = {"url": url_to_scan}
        response = requests.post(PLAYWRIGHT_SCANNER_URL, json=scanner_payload, timeout=PLAYWRIGHT_SCANNER_TIMEOUT_SECONDS)
        response.raise_for_status()
        
        try:
            # Update playwright_results with the actual response from the scanner
            playwright_results.update(response.json()) 
            print(f"Playwright scan successful for {url_to_scan}. Final URL: {playwright_results.get('final_url', 'N/A')}")
        except json.JSONDecodeError:
            print(f"Could not decode JSON response from Playwright scanner for {url_to_scan}. Raw response: {response.text[:500]}")
            playwright_results["error"] = "Invalid JSON response from Playwright scanner"
            playwright_results["raw_response_snippet"] = response.text[:500]

    except requests.exceptions.Timeout:
        print(f"Timeout calling Playwright scanner for {url_to_scan}")
        playwright_results["error"] = "Playwright scanner timed out"
    except requests.exceptions.ConnectionError:
        print(f"Connection error calling Playwright scanner for {url_to_scan}")
        playwright_results["error"] = "Playwright scanner connection refused"
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error calling Playwright scanner for {url_to_scan}: {http_err}")
        playwright_results["error"] = f"Playwright scanner HTTP error: {http_err.response.status_code}"
        try:
            playwright_results["details"] = http_err.response.json().get("error", http_err.response.text[:200])
        except json.JSONDecodeError:
            playwright_results["details"] = http_err.response.text[:200]
    except requests.exceptions.RequestException as req_err:
        print(f"Error calling Playwright scanner for {url_to_scan}: {req_err}")
        playwright_results["error"] = f"Playwright scanner request failed: {str(req_err)}"
    
    # --- Ensure standard fields and new detailed fields exist with defaults ---
    # Basic fields already present in your original code:
    playwright_results.setdefault('final_url', 'N/A')
    playwright_results.setdefault('page_title', 'N/A')
    playwright_results.setdefault('status_code', 'N/A') # Can be string or int, frontend handles N/A
    playwright_results.setdefault('alerts_found', [])
    playwright_results.setdefault('redirection_history', [])

    # New fields based on your Playwright service output:
    playwright_results.setdefault('original_url', playwright_results.get('url_submitted_for_scan', url_to_scan)) # Ensure original_url is present
    playwright_results.setdefault('screenshot_base64', None) # Frontend expects this, None or "" is fine
    playwright_results.setdefault('has_iframes', None) # Booleans, None if not determined, frontend treats None/false similarly
    playwright_results.setdefault('has_input_fields', None)
    playwright_results.setdefault('has_password_field', None)
    playwright_results.setdefault('number_of_external_links', None) # Numbers, None if not determined
    playwright_results.setdefault('number_of_forms', None)
    playwright_results.setdefault('number_of_links', None)
    playwright_results.setdefault('number_of_redirects', None)
    playwright_results.setdefault('number_of_script_tags', None)
    playwright_results.setdefault('page_content_length', None)
    playwright_results.setdefault('suspicious_words_found', []) # List
    playwright_results.setdefault('url_contains_ip', None) # Boolean
    playwright_results.setdefault('url_length', None) # Number
    playwright_results.setdefault('url_path_entropy', None) # Float or None
    playwright_results.setdefault('url_query_entropy', None) # Float or None
    
    # Domain Info (nested object)
    domain_info_data = playwright_results.get('domain_info', {}) # Get existing or new dict
    domain_info_data.setdefault('domain_age_days', None)
    domain_info_data.setdefault('hostname_matches_ssl_cert', None) # Boolean or None
    domain_info_data.setdefault('ssl_certificate_expiry_days', None)
    domain_info_data.setdefault('ssl_issuer', 'N/A')
    domain_info_data.setdefault('ssl_protocol', 'N/A')
    domain_info_data.setdefault('ssl_subject_name', 'N/A')
    domain_info_data.setdefault('ssl_valid', None) # Boolean or None
    playwright_results['domain_info'] = domain_info_data # Ensure the updated/defaulted dict is set back

    # The 'error' key is already handled by the try-except blocks above.
    # 'details' for HTTP errors is also handled.
    
    print(f"Playwright results (with defaults) for {url_to_scan}: {json.dumps(playwright_results, indent=2, default=str)}") # Use default=str for things like datetime if they ever creep in
    return playwright_results

if __name__ == '__main__':
    print("Starting Phishing Detection Backend...")
    if not os.path.exists('./model_cache'):
        os.makedirs('./model_cache')
        print(f"Created cache directory: ./model_cache")

    print(f"Loaded {len(TRUSTED_DOMAINS)} trusted domains and {len(TRUSTED_EMAIL_PATTERNS)} trusted email patterns.")
    print(f"URL Classification Model Ready: {url_classification_pipeline is not None}")
    print(f"Email Content Model Ready: {email_content_pipeline is not None}")
    print(f"Playwright Scanner URL: {PLAYWRIGHT_SCANNER_URL}")
    print("Backend will be available at: http://localhost:5102")
    print("Endpoints: GET /health, POST /analyze-email, POST /analyze-url, GET /stats")
    print("\nReady to receive requests from Chrome extension...")
    
    app.run(host='localhost', port=5102, debug=True, threaded=True) # Use threaded=True for multiple requests