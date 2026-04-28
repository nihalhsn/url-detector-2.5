import os
from dotenv import load_dotenv
from pathlib import Path
env_path = Path(__file__).parent / '.env'

load_dotenv(dotenv_path=env_path, override=True)

# DEBUG
print(f".env path: {env_path}")
print(f".env exists: {env_path.exists()}")
print(f"VT_KEY: {os.getenv('VIRUSTOTAL_API_KEY', 'NOT_FOUND')[:10]}...")
print(f"GSB_KEY: {os.getenv('GSB_API_KEY', 'NOT_FOUND')[:10]}...")

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash, send_file
from functools import wraps
import whois
import re
import hashlib
import json
from datetime import datetime, timedelta
import requests
import pickle
import numpy as np
from urllib.parse import urlparse, unquote
import tldextract
import signal
from contextlib import contextmanager
import pandas as pd
from werkzeug.utils import secure_filename
import math
from collections import Counter
import threading
import ipaddress
import bcrypt
import io
import csv
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from database import Database

# ============ LOGGING SETUP ============
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishguard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('phishguard')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32).hex())

# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ============ CONFIGURATION ============
CONFIG = {
    'VIRUSTOTAL_API_KEY': os.environ.get('VIRUSTOTAL_API_KEY', ''),
    'GSB_API_KEY': os.environ.get('GSB_API_KEY', ''),
    'PHISHTANK_API_URL': 'http://data.phishtank.com/data/online-valid.json',
    'ML_MODEL_PATH': os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishing_model.pkl'),
    'MODELS_DIR': os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models'),
    'ADMIN_USERNAME': os.environ.get('ADMIN_USER', 'admin'),
    'ADMIN_PASSWORD_HASH': os.environ.get('ADMIN_PASS_HASH'),
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOGIN_LOCKOUT_MINUTES': 1,
    'SESSION_TIMEOUT_MINUTES': 20,
    'THREAT_INTEL_ENABLED': os.environ.get('THREAT_INTEL_ENABLED', 'true').lower() in ('true', '1', 'yes'),
    'REQUEST_TIMEOUT': 10,
    'DOMAIN_AGE_TIMEOUT': 5,
    'SCAN_CACHE_ENABLED': True,
    'SCAN_CACHE_TTL_SECONDS': 300,
    'URL_EXPAND_TIMEOUT': 8,
    'MAX_URL_LENGTH': 2048,
    'ENABLE_ASYNC_ANALYSIS': False
}

# Ensure models directory exists
os.makedirs(CONFIG['MODELS_DIR'], exist_ok=True)

# ============ TRUSTED DOMAINS WHITELIST (reduces false positives) ============
TRUSTED_DOMAINS = {
    'chatgpt.com', 'openai.com', 'platform.openai.com', 'api.openai.com',
    'kimi.com', 'kimi.moonshot.cn', 'moonshot.cn',
    'claude.ai', 'anthropic.com',
    'gemini.google.com', 'bard.google.com',
    'copilot.microsoft.com', 'bing.com', 'microsoft.com',
    'perplexity.ai', 'poe.com', 'huggingface.co',
    'github.com', 'gitlab.com', 'stackoverflow.com',
    'google.com', 'youtube.com', 'gmail.com',
    'amazon.com', 'aws.amazon.com',
    'apple.com', 'icloud.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
    'paypal.com', 'stripe.com',
    'reddit.com', 'discord.com', 'twitch.tv',
    'netflix.com', 'spotify.com',
    'dropbox.com', 'notion.so', 'figma.com',
    'vercel.com', 'heroku.com', 'render.com',
    'cloudflare.com', 'akamai.com',
    'wikipedia.org', 'wikimedia.org',
    'medium.com', 'substack.com',
    'docs.google.com', 'drive.google.com', 'sheets.google.com',
    'calendar.google.com', 'meet.google.com',
}

# Known URL shortener domains for expansion
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
    'short.link', 'is.gd', 'cli.gs', 'pic.gd', 'DwarfURL.com', 'ow.ly',
    'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'tr.im',
    'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to',
    'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com',
    'snipr.com', 'flic.kr', 'loopt.us', 'doiop.com', 'twitthis.com',
    'ht.ly', 'RubyURL.com', 'om.ly', 'linkbee.com', 'linkbun.ch',
    'zz.gd', 'x.vu', 'w34.us', 'tiny.pl', 'ur1.ca', 'tr.my',
    'short.ie', 'korta.nu', 'flpbd.it', 'wp.me', 'short.ie', 'rln.kr',
    'wp.me', 'u.nu', 'tu.qs', 'razr.to', 'qr.net', '1url.com',
    'tweez.me', 'sk.gy', 'gkl.st', 'ri.ms', 'celly.me', 'url.ie',
    'idek.net', 'knb.im', 'goo-gl.me', 'hmm.ph', 'xrl.in', 'shrten.com',
    'bc.vc', 'twiturl.de', 'cutt.us', 'u.to', 'fun.ly', 'ow.ly',
    'j.mp', 'twtr.to', 'urlenco.de', 'ne1.net', 'b23.ru', 'short.url',
    'v.gd', 'shorturl.at', 'rebrand.ly', 'bl.ink', 'short.io',
    'sniply.io', 'branch.io', 'clickmeter.com', 'pixelme.me',
}

# ============ BRAND DATABASE ============
TRUSTED_BRANDS = {
    'financial': ['paypal', 'chase', 'bankofamerica', 'wellsfargo', 'citi', 'citibank', 'amex', 'americanexpress',
                  'visa', 'mastercard', 'discover', 'stripe', 'square', 'venmo', 'zelle', 'westernunion',
                  'bank', 'creditunion', 'savings', 'checking', 'account', 'wallet'],
    'technology': ['google', 'gmail', 'youtube', 'apple', 'icloud', 'microsoft', 'outlook', 'hotmail', 'live',
                   'amazon', 'aws', 'facebook', 'meta', 'instagram', 'whatsapp', 'twitter', 'linkedin',
                   'github', 'gitlab', 'dropbox', 'slack', 'zoom', 'teams', 'skype', 'adobe', 'oracle'],
    'retail': ['ebay', 'etsy', 'shopify', 'walmart', 'target', 'bestbuy', 'costco', 'nordstrom', 'macys',
               'amazon', 'aliexpress', 'wish', 'wayfair', 'home depot', 'lowes', 'ikea'],
    'social': ['facebook', 'instagram', 'twitter', 'tiktok', 'snapchat', 'reddit', 'linkedin', 'pinterest',
               'tumblr', 'twitch', 'discord', 'telegram', 'signal'],
    'government': ['irs', 'ssa', 'uscis', 'gov', 'treasury', 'fda', 'cdc', 'epa', 'usps', 'state.gov']
}

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.buzz', '.click', '.work', '.date',
                   '.racing', '.loan', '.download', '.men', '.gdn', '.stream', '.trade', '.win',
                   '.bid', '.country', '.link', '.kim', '.science']

SUSPICIOUS_KEYWORDS = {
    'urgent': ['urgent', 'immediate', 'now', 'today', 'expires', 'limited', 'act now', 'hurry'],
    'security': ['verify', 'confirm', 'validate', 'secure', 'security', 'protection', 'suspicious', 'unusual activity'],
    'account': ['login', 'signin', 'authenticate', 'password', 'credential', 'account', 'update', 'restore', 'recover'],
    'financial': ['payment', 'billing', 'invoice', 'transaction', 'refund', 'prize', 'won', 'winner', 'lottery'],
    'sensitive': ['ssn', 'social security', 'tax id', 'passport', 'dob', 'birthdate', 'mother maiden']
}

# ============ SCAN CACHE ============
scan_cache = {}
scan_cache_lock = threading.Lock()

def get_cached_scan(url: str) -> Optional[Dict]:
    if not CONFIG.get('SCAN_CACHE_ENABLED', True):
        return None
    with scan_cache_lock:
        if url in scan_cache:
            cached = scan_cache[url]
            if datetime.now() - cached['timestamp'] < timedelta(seconds=CONFIG['SCAN_CACHE_TTL_SECONDS']):
                logger.info(f"Cache hit for URL: {url}")
                return cached['result']
            else:
                del scan_cache[url]
    return None

def set_cached_scan(url: str, result: Dict):
    if not CONFIG.get('SCAN_CACHE_ENABLED', True):
        return
    with scan_cache_lock:
        scan_cache[url] = {
            'result': result,
            'timestamp': datetime.now()
        }
        # Limit cache size
        if len(scan_cache) > 1000:
            oldest = min(scan_cache.items(), key=lambda x: x[1]['timestamp'])
            del scan_cache[oldest[0]]

# ============ LOGIN ATTEMPT TRACKING ============
login_attempts = {}

def check_login_lockout(ip):
    if ip in login_attempts:
        attempts, last_attempt = login_attempts[ip]
        if attempts >= CONFIG['MAX_LOGIN_ATTEMPTS']:
            lockout_time = last_attempt + timedelta(minutes=CONFIG['LOGIN_LOCKOUT_MINUTES'])
            if datetime.now() < lockout_time:
                remaining = int((lockout_time - datetime.now()).total_seconds() / 60)
                return False, f"Account locked. Try again in {remaining} minutes"
            else:
                login_attempts[ip] = (0, datetime.now())
    return True, ""

def record_login_attempt(ip, success):
    if ip not in login_attempts:
        login_attempts[ip] = (0, datetime.now())
    attempts, _ = login_attempts[ip]
    if success:
        login_attempts[ip] = (0, datetime.now())
    else:
        login_attempts[ip] = (attempts + 1, datetime.now())

# ============ AUTHENTICATION DECORATORS ============
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(minutes=CONFIG['SESSION_TIMEOUT_MINUTES']):
                session.clear()
                flash('Session expired. Please login again.', 'warning')
                return redirect(url_for('admin_login'))
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

# ============ TIMEOUT HANDLER ============
class TimeoutException(Exception):
    pass

@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

# ============ URL EXPANSION UTILITY ============
def expand_short_url(url: str) -> Tuple[str, bool]:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        if domain in URL_SHORTENERS:
            logger.info(f"Expanding shortened URL: {url}")
            try:
                response = requests.head(
                    url, 
                    allow_redirects=True, 
                    timeout=CONFIG['URL_EXPAND_TIMEOUT'],
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
            except requests.exceptions.RequestException:
                response = requests.get(
                    url,
                    allow_redirects=True,
                    timeout=CONFIG['URL_EXPAND_TIMEOUT'],
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
            expanded = response.url
            if expanded != url:
                logger.info(f"Expanded {url} -> {expanded}")
                return expanded, True
    except Exception as e:
        logger.warning(f"URL expansion failed for {url}: {e}")
    return url, False

def is_trusted_domain(registered_domain: str) -> bool:
    """Check if domain is in the trusted whitelist."""
    rd_lower = registered_domain.lower()
    for trusted in TRUSTED_DOMAINS:
        if rd_lower == trusted or rd_lower.endswith('.' + trusted):
            return True
    return False

# ============ LAYER 1: URL PARSER ============
class URLParser:
    def __init__(self, url):
        self.original_url = url
        self.normalized_url = self._normalize_url(url)
        self.parsed = urlparse(self.normalized_url)
        self.extracted = tldextract.extract(self.normalized_url)

        self.protocol = self.parsed.scheme
        self.subdomain = self.extracted.subdomain
        self.domain = self.extracted.domain
        self.suffix = self.extracted.suffix
        self.registered_domain = f"{self.domain}.{self.suffix}" if self.suffix else self.domain
        self.full_domain = f"{self.subdomain}.{self.registered_domain}" if self.subdomain else self.registered_domain
        self.path = unquote(self.parsed.path)
        self.path_components = [p for p in self.path.split('/') if p]
        self.query = unquote(self.parsed.query)
        self.fragment = self.parsed.fragment
        self.port = self.parsed.port
        self.is_trusted = is_trusted_domain(self.registered_domain)

    def _normalize_url(self, url):
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        # Don't strip www. - it can affect subdomain analysis
        return url

    def get_components(self):
        return {
            'original': self.original_url,
            'normalized': self.normalized_url,
            'protocol': self.protocol,
            'subdomain': self.subdomain,
            'domain': self.domain,
            'suffix': self.suffix,
            'registered_domain': self.registered_domain,
            'full_domain': self.full_domain,
            'path': self.path,
            'query': self.query,
            'path_components': self.path_components,
            'query_params': self._parse_query_params(),
            'is_trusted': self.is_trusted
        }

    def _parse_query_params(self):
        params = {}
        if self.query:
            for pair in self.query.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value
        return params

    def is_ip_based(self):
        try:
            ipaddress.ip_address(self.domain)
            return True
        except ValueError:
            return False

# ============ LAYER 2: BRAND IMPERSONATION DETECTOR ============
class BrandImpersonationDetector:
    def __init__(self, url_parser):
        self.parser = url_parser
        self.findings = []
        self.impersonated_brand = None
        self.confidence = 0

    def analyze(self):
        # Skip brand checks for trusted domains to reduce false positives
        if self.parser.is_trusted:
            return self._get_result()

        self._check_subdomain_impersonation()
        self._check_path_impersonation()
        self._check_typosquatting()
        self._check_combined_attacks()
        return self._get_result()

    def _check_subdomain_impersonation(self):
        subdomain = self.parser.subdomain.lower()

        if not subdomain or subdomain in ['www', 'mail', 'ftp', 'api', 'cdn', 'app', 'www1', 'www2']:
            return

        for category, brands in TRUSTED_BRANDS.items():
            for brand in brands:
                if len(brand) <= 2:  # Skip single/double char brands
                    continue
                if brand in subdomain:
                    # More precise check: brand should not be the actual domain
                    if brand not in self.parser.registered_domain.lower():
                        # Additional check: is the brand a substring of a legitimate word?
                        # e.g., "app" in "apple" should not trigger
                        if self._is_legitimate_subdomain(subdomain, brand):
                            continue
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'type': 'subdomain_impersonation',
                            'brand': brand,
                            'description': f"{brand.title()} appears in subdomain '{subdomain}' but not in registered domain '{self.parser.registered_domain}'",
                            'evidence': f"subdomain={subdomain}, domain={self.parser.registered_domain}"
                        })
                        self.impersonated_brand = brand
                        self.confidence = max(self.confidence, 0.9)
                        return

    def _is_legitimate_subdomain(self, subdomain: str, brand: str) -> bool:
        if len(brand) <= 3:
            pattern = r'(^|\.)' + re.escape(brand) + r'(\.|$)'
            return bool(re.search(pattern, subdomain))
        # Common legitimate subdomains that contain brand names
        legit_patterns = {
            'google': ['googleapis', 'googleusercontent', 'googlevideo'],
            'apple': ['apple-dns', 'apple-cloudkit'],
            'microsoft': ['microsoftonline', 'microsofttranslator'],
            'facebook': ['facebook-', 'fbcdn'],
            'amazon': ['amazonaws', 'amazonses'],
            'github': ['githubusercontent'],
        }
        for b, patterns in legit_patterns.items():
            if b == brand:
                for p in patterns:
                    if p in subdomain:
                        return True
        return False

    def _check_path_impersonation(self):
        path_lower = self.parser.path.lower()

        # Skip path checks for trusted domains
        if self.parser.is_trusted:
            return

        for category, brands in TRUSTED_BRANDS.items():
            for brand in brands:
                if len(brand) <= 2:  # Skip single/double char brands
                    continue
                if brand in path_lower:
                    if brand not in self.parser.registered_domain.lower():
                        login_indicators = ['login', 'signin', 'auth', 'verify', 'secure', 'authenticate']
                        has_login_context = any(ind in path_lower for ind in login_indicators)

                        severity = 'CRITICAL' if has_login_context else 'HIGH'
                        self.findings.append({
                            'severity': severity,
                            'type': 'path_impersonation',
                            'brand': brand,
                            'description': f"{brand.title()} in URL path on unrelated domain",
                            'evidence': f"path={self.parser.path}, domain={self.parser.registered_domain}",
                            'has_login_context': has_login_context
                        })
                        if not self.impersonated_brand:
                            self.impersonated_brand = brand
                        self.confidence = max(self.confidence, 0.85 if has_login_context else 0.7)

    def _check_typosquatting(self):
        domain = self.parser.domain

        common_substitutions = {
            'paypa1': 'paypal',
            'amaz0n': 'amazon',
            'g00gle': 'google',
            'micr0soft': 'microsoft',
            'rnicrosoft': 'microsoft',
            'faceb00k': 'facebook',
            'app1e': 'apple',
            '1cloud': 'icloud'
        }

        for typo, original in common_substitutions.items():
            if typo in domain:
                self.findings.append({
                    'severity': 'HIGH',
                    'type': 'typosquatting',
                    'brand': original,
                    'description': f"Possible typosquatting: '{typo}' mimics '{original}'",
                    'evidence': f"domain={domain}"
                })
                self.impersonated_brand = original
                self.confidence = max(self.confidence, 0.8)

    def _check_combined_attacks(self):
        found_brands = set()
        all_text = f"{self.parser.subdomain} {self.parser.path}".lower()

        for category, brands in TRUSTED_BRANDS.items():
            for brand in brands:
                if len(brand) <= 2:
                    continue
                if brand in all_text or brand in self.parser.domain:
                    found_brands.add(brand)

        if len(found_brands) > 1:
            self.findings.append({
                'severity': 'HIGH',
                'type': 'multi_brand_attack',
                'brands': list(found_brands),
                'description': f"Multiple brands detected: {', '.join(found_brands[:3])}",
                'evidence': "Unusual to have multiple competing brands in one URL"
            })
            self.confidence = max(self.confidence, 0.75)

    def _get_result(self):
        return {
            'impersonation_detected': len(self.findings) > 0,
            'impersonated_brand': self.impersonated_brand,
            'findings': self.findings,
            'confidence': self.confidence,
            'severity': self._get_max_severity()
        }

    def _get_max_severity(self):
        if not self.findings:
            return 'NONE'
        severities = [f['severity'] for f in self.findings]
        if 'CRITICAL' in severities:
            return 'CRITICAL'
        if 'HIGH' in severities:
            return 'HIGH'
        return 'MEDIUM'

# ============ LAYER 3: STRUCTURAL ANOMALY DETECTOR ============
class StructuralAnomalyDetector:
    def __init__(self, url_parser):
        self.parser = url_parser
        self.anomalies = []

    def analyze(self):
        # Trusted domains get minimal structural checks
        if self.parser.is_trusted:
            self._check_at_symbol()
            self._check_ip_based_url()
            return {
                'anomalies_detected': len(self.anomalies) > 0,
                'anomalies': self.anomalies,
                'anomaly_score': self._calculate_anomaly_score(),
                'suspicious_patterns': [a['type'] for a in self.anomalies]
            }

        self._check_suspicious_tld()
        self._check_ip_based_url()
        self._check_at_symbol()
        self._check_excessive_dots()
        self._check_url_length()
        self._check_path_depth()
        self._check_encoding_obfuscation()
        self._check_port_anomaly()
        self._check_double_slash_redirect()
        return {
            'anomalies_detected': len(self.anomalies) > 0,
            'anomalies': self.anomalies,
            'anomaly_score': self._calculate_anomaly_score(),
            'suspicious_patterns': [a['type'] for a in self.anomalies]
        }

    def _check_suspicious_tld(self):
        suffix = f".{self.parser.suffix}" if self.parser.suffix else ""

        for tld in SUSPICIOUS_TLDS:
            if suffix == tld or self.parser.registered_domain.endswith(tld):
                self.anomalies.append({
                    'severity': 'MEDIUM',
                    'type': 'suspicious_tld',
                    'description': f"Domain uses suspicious TLD '{tld}' commonly used for phishing",
                    'evidence': f"suffix={self.parser.suffix}"
                })
                break

    def _check_ip_based_url(self):
        if self.parser.is_ip_based():
            self.anomalies.append({
                'severity': 'HIGH',
                'type': 'ip_based_url',
                'description': "URL uses IP address instead of domain name - common in phishing",
                'evidence': f"ip={self.parser.domain}"
            })

    def _check_at_symbol(self):
        if '@' in self.parser.normalized_url:
            self.anomalies.append({
                'severity': 'CRITICAL',
                'type': 'at_symbol',
                'description': "URL contains '@' symbol - potential credential harvesting or redirect attack",
                'evidence': "username@hostname pattern detected"
            })

    def _check_excessive_dots(self):
        # Count dots in domain part only, not full URL
        domain_part = self.parser.full_domain
        dot_count = domain_part.count('.')
        if dot_count > 4:
            self.anomalies.append({
                'severity': 'MEDIUM',
                'type': 'excessive_dots',
                'description': f"Unusual number of dots ({dot_count}) in domain suggesting subdomain abuse",
                'evidence': f"dot_count={dot_count}"
            })

    def _check_url_length(self):
        length = len(self.parser.normalized_url)
        # Increased thresholds: modern apps use long URLs with UUIDs and tokens
        if length > 250:
            severity = 'HIGH' if length > 500 else 'MEDIUM'
            self.anomalies.append({
                'severity': severity,
                'type': 'excessive_length',
                'description': f"URL is unusually long ({length} chars) - possible obfuscation",
                'evidence': f"length={length}"
            })

    def _check_path_depth(self):
        depth = len(self.parser.path_components)
        if depth > 8:
            self.anomalies.append({
                'severity': 'LOW',
                'type': 'deep_path',
                'description': f"Deep directory structure ({depth} levels) - unusual for legitimate sites",
                'evidence': f"path_depth={depth}"
            })

    def _check_encoding_obfuscation(self):
        if '%' in self.parser.original_url:
            encoded_chars = len(re.findall(r'%[0-9a-fA-F]{2}', self.parser.original_url))
            if encoded_chars > 10:
                self.anomalies.append({
                    'severity': 'MEDIUM',
                    'type': 'encoding_obfuscation',
                    'description': f"Heavy URL encoding ({encoded_chars} encoded characters) - possible obfuscation",
                    'evidence': "Excessive percent-encoding detected"
                })

    def _check_port_anomaly(self):
        if self.parser.port and self.parser.port not in [80, 443]:
            self.anomalies.append({
                'severity': 'MEDIUM',
                'type': 'non_standard_port',
                'description': f"Unusual port number {self.parser.port}",
                'evidence': f"port={self.parser.port}"
            })

    def _check_double_slash_redirect(self):
        if '//' in self.parser.path:
            self.anomalies.append({
                'severity': 'MEDIUM',
                'type': 'double_slash_redirect',
                'description': "Double slash in path - possible redirect or protocol confusion attack",
                'evidence': f"path={self.parser.path}"
            })

    def _calculate_anomaly_score(self):
        weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 3, 'LOW': 1}
        return sum(weights.get(a['severity'], 0) for a in self.anomalies)

# ============ LAYER 4: KEYWORD CONTEXT ANALYZER ============
class KeywordContextAnalyzer:
    def __init__(self, url_parser):
        self.parser = url_parser
        self.findings = []

    def analyze(self):
        # For trusted domains, only check for credential harvesting in paths
        if self.parser.is_trusted:
            path_lower = self.parser.path.lower()
            login_patterns = ['login', 'signin', 'authenticate', 'password', 'credential']
            has_login = any(p in path_lower for p in login_patterns)
            if has_login and not self._is_legitimate_login_path():
                self.findings.append({
                    'category': 'credential_harvesting',
                    'keywords': [p for p in login_patterns if p in path_lower],
                    'severity': 'MEDIUM',
                    'description': "Login context on trusted domain (verify SSL)",
                    'context': "Trusted domain with login page - normal behavior"
                })
            return {
                'keywords_detected': len(self.findings) > 0,
                'findings': self.findings,
                'context_score': self._calculate_context_score(),
                'primary_intent': self._determine_intent()
            }

        full_text = f"{self.parser.subdomain} {self.parser.path} {self.parser.query}".lower()

        self._check_urgency_context(full_text)
        self._check_security_context(full_text)
        self._check_financial_context(full_text)
        self._check_credential_context(full_text)
        self._check_suspicious_combinations(full_text)

        return {
            'keywords_detected': len(self.findings) > 0,
            'findings': self.findings,
            'context_score': self._calculate_context_score(),
            'primary_intent': self._determine_intent()
        }

    def _is_legitimate_login_path(self) -> bool:
        """Check if login path is on a known legitimate domain."""
        legit_login_paths = ['/login', '/signin', '/auth', '/authenticate', '/oauth']
        return any(self.parser.path.lower().startswith(p) for p in legit_login_paths)

    def _check_urgency_context(self, text):
        found = [k for k in SUSPICIOUS_KEYWORDS['urgent'] if k in text]
        if found:
            self.findings.append({
                'category': 'urgency',
                'keywords': found,
                'severity': 'MEDIUM',
                'description': f"Urgency indicators: {', '.join(found[:3])}",
                'context': "Creates time pressure to bypass security thinking"
            })

    def _check_security_context(self, text):
        found = [k for k in SUSPICIOUS_KEYWORDS['security'] if k in text]
        if found:
            security_vendors = ['symantec', 'mcafee', 'norton', 'kaspersky', 'avast']
            is_vendor = any(v in self.parser.registered_domain for v in security_vendors)

            if not is_vendor:
                self.findings.append({
                    'category': 'security_urgency',
                    'keywords': found,
                    'severity': 'HIGH',
                    'description': f"Security keywords on non-security site: {', '.join(found[:3])}",
                    'context': "Fake security warnings common in phishing"
                })

    def _check_financial_context(self, text):
        found = [k for k in SUSPICIOUS_KEYWORDS['financial'] if k in text]
        if found:
            self.findings.append({
                'category': 'financial',
                'keywords': found,
                'severity': 'MEDIUM',
                'description': f"Financial indicators: {', '.join(found[:3])}",
                'context': "Financial targeting detected"
            })

    def _check_credential_context(self, text):
        found = [k for k in SUSPICIOUS_KEYWORDS['account'] if k in text]

        login_patterns = ['login', 'signin', 'authenticate', 'password', 'credential']
        has_login = any(p in text for p in login_patterns)

        if found and has_login:
            self.findings.append({
                'category': 'credential_harvesting',
                'keywords': found,
                'severity': 'HIGH',
                'description': f"Credential harvesting context: {', '.join(found[:3])}",
                'context': "URL designed to capture login credentials"
            })

    def _check_suspicious_combinations(self, text):
        dangerous_combos = [
            (['verify', 'account'], ['security', 'suspended']),
            (['update', 'payment'], ['confirm', 'billing']),
            (['suspended', 'account'], ['restore', 'verify'])
        ]

        for combo in dangerous_combos:
            if all(any(k in text for k in group) for group in combo):
                self.findings.append({
                    'category': 'suspicious_combination',
                    'keywords': [k for group in combo for k in group],
                    'severity': 'HIGH',
                    'description': f"Dangerous keyword combination detected",
                    'context': "Classic phishing phrase pattern identified"
                })
                break

    def _calculate_context_score(self):
        weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return sum(weights.get(f['severity'], 1) for f in self.findings)

    def _determine_intent(self):
        categories = [f['category'] for f in self.findings]
        if 'credential_harvesting' in categories:
            return 'CREDENTIAL_THEFT'
        if 'financial' in categories:
            return 'FINANCIAL_FRAUD'
        if 'security_urgency' in categories:
            return 'FAKE_SECURITY_ALERT'
        if 'urgency' in categories:
            return 'URGENCY_MANIPULATION'
        return 'UNKNOWN'

# ============ LAYER 5: WEIGHTED RISK SCORING ENGINE ============
class RiskScoringEngine:
    WEIGHTS = {
        'brand_subdomain_impersonation': 10,
        'at_symbol': 10,
        'typosquatting': 9,
        'ip_based_url': 8,
        'brand_path_impersonation_login': 7,
        'credential_harvesting_context': 6,
        'suspicious_tld': 4,
        'security_keywords_non_vendor': 4,
        'encoding_obfuscation': 3,
        'excessive_length': 3,
        'non_standard_port': 3,
        'double_slash_redirect': 3,
        'no_https': 2,
        'deep_path': 1,
        'excessive_dots': 1,
        'urgency_keywords': 1,
        'ml_phishing_prediction': 5,
        'virustotal_flagged': 8,
        'google_safe_browsing_flagged': 10,
        'phishtank_known': 10
    }

    def __init__(self, url_parser, brand_result, anomaly_result, keyword_result, ml_result=None, threat_result=None):
        self.parser = url_parser
        self.brand = brand_result
        self.anomaly = anomaly_result
        self.keyword = keyword_result
        self.ml = ml_result or {}
        self.threat = threat_result or {}

    def calculate(self):
        score = 0
        factors = []
        max_possible = 0

        if self.brand['impersonation_detected']:
            for finding in self.brand['findings']:
                if finding['type'] == 'subdomain_impersonation':
                    score += self.WEIGHTS['brand_subdomain_impersonation']
                    factors.append({
                        'layer': 'BRAND',
                        'factor': 'Brand in subdomain (not in domain)',
                        'severity': 'CRITICAL',
                        'weight': self.WEIGHTS['brand_subdomain_impersonation'],
                        'description': finding['description']
                    })
                    max_possible += self.WEIGHTS['brand_subdomain_impersonation']
                elif finding['type'] == 'path_impersonation':
                    weight = self.WEIGHTS['brand_path_impersonation_login'] if finding.get('has_login_context') else 5
                    score += weight
                    factors.append({
                        'layer': 'BRAND',
                        'factor': 'Brand impersonation in path',
                        'severity': finding['severity'],
                        'weight': weight,
                        'description': finding['description']
                    })
                    max_possible += weight
                elif finding['type'] == 'typosquatting':
                    score += self.WEIGHTS['typosquatting']
                    factors.append({
                        'layer': 'BRAND',
                        'factor': 'Typosquatting detected',
                        'severity': 'HIGH',
                        'weight': self.WEIGHTS['typosquatting'],
                        'description': finding['description']
                    })
                    max_possible += self.WEIGHTS['typosquatting']

        for anomaly in self.anomaly['anomalies']:
            weight_key = anomaly['type']
            if weight_key in self.WEIGHTS:
                weight = self.WEIGHTS[weight_key]
                score += weight
                factors.append({
                    'layer': 'STRUCTURE',
                    'factor': anomaly['type'].replace('_', ' ').title(),
                    'severity': anomaly['severity'],
                    'weight': weight,
                    'description': anomaly['description']
                })
                max_possible += weight

        for finding in self.keyword['findings']:
            if finding['category'] == 'credential_harvesting':
                w = self.WEIGHTS['credential_harvesting_context']
                score += w
                factors.append({...})
                max_possible += w
            elif finding['severity'] == 'HIGH':
                w = self.WEIGHTS['security_keywords_non_vendor']
                score += w
                factors.append({...})
                max_possible += w
            else:
                w = self.WEIGHTS['urgency_keywords']
                score += w
                factors.append({...})
                max_possible += w

        ml_confidence = float(self.ml.get('phishing_probability', 0))
        if ml_confidence > 0.7:
            ml_contribution = self.WEIGHTS['ml_phishing_prediction'] * ml_confidence
            score += ml_contribution
            factors.append({
                'layer': 'ML_MODEL',
                'factor': 'ML phishing prediction',
                'severity': 'HIGH' if ml_confidence > 0.8 else 'MEDIUM',
                'weight': round(ml_contribution, 2),
                'description': f"Machine learning model {ml_confidence:.1%} confident of phishing"
            })
            max_possible += self.WEIGHTS['ml_phishing_prediction']

        if self.threat.get('virustotal', {}).get('reputation_score', 0) > 3:
            score += self.WEIGHTS['virustotal_flagged']
            factors.append({
                'layer': 'THREAT_INTEL',
                'factor': 'VirusTotal detection',
                'severity': 'HIGH',
                'weight': self.WEIGHTS['virustotal_flagged'],
                'description': f"{self.threat['virustotal']['reputation_score']} security vendors flagged this URL"
            })
            max_possible += self.WEIGHTS['virustotal_flagged']

        if self.threat.get('google_safe_browsing', {}).get('threat_found'):
            score += self.WEIGHTS['google_safe_browsing_flagged']
            factors.append({
                'layer': 'THREAT_INTEL',
                'factor': 'Google Safe Browsing block',
                'severity': 'CRITICAL',
                'weight': self.WEIGHTS['google_safe_browsing_flagged'],
                'description': f"Google detected: {self.threat['google_safe_browsing'].get('threat_type', 'Threat')}"
            })
            max_possible += self.WEIGHTS['google_safe_browsing_flagged']

        if self.parser.protocol != 'https':
            score += self.WEIGHTS['no_https']
            factors.append({
                'layer': 'SECURITY',
                'factor': 'No HTTPS encryption',
                'severity': 'LOW',
                'weight': self.WEIGHTS['no_https'],
                'description': "Connection not encrypted - credential risk"
            })
            max_possible += self.WEIGHTS['no_https']

        normalized_score = min(100, int((score / max(max_possible, 1)) * 100))

        # Trusted domain with low score = very high confidence safe
        if self.parser.is_trusted and normalized_score < 20:
            confidence = 0.98
        else:
            confidence = self._calculate_confidence(
                factors, 
                float(self.ml.get('confidence', 0.5)), 
                normalized_score
            )

        return {
            'raw_score': round(score, 2),
            'max_possible': max_possible,
            'normalized_score': normalized_score,
            'risk_level': self._get_risk_level(normalized_score),
            'confidence': confidence,
            'factors': sorted(factors, key=lambda x: x['weight'], reverse=True),
            'primary_threats': [f for f in factors if f['severity'] in ['CRITICAL', 'HIGH']][:3]
        }

    def _get_risk_level(self, score):
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 15:
            return 'LOW'
        else:
            return 'MINIMAL'

    def _calculate_confidence(self, factors, ml_confidence=0.5, risk_score=0):
        # No factors + safe score = high confidence it's safe
        if not factors and risk_score < 15:
            return 0.95  # 95% confident it's safe
            
        # No factors but elevated score = use ML confidence
        if not factors:
            return max(0.5, ml_confidence)

        # Count evidence by severity
        critical_count = sum(1 for f in factors if f['severity'] == 'CRITICAL')
        high_count = sum(1 for f in factors if f['severity'] == 'HIGH')
        medium_count = sum(1 for f in factors if f['severity'] == 'MEDIUM')
        
        total_weighted = critical_count * 3 + high_count * 2 + medium_count * 1
        
        # Base confidence from evidence strength
        if critical_count > 0:
            base = 0.75
        elif high_count > 0:
            base = 0.65
        elif medium_count > 0:
            base = 0.55
        else:
            base = 0.50
            
        # Boost for multiple independent findings
        evidence_bonus = min(0.25, total_weighted * 0.05)
        
        # ML agreement bonus
        ml_agreement = 0
        if ml_confidence > 0.7 and risk_score > 40:
            ml_agreement = 0.10
        elif ml_confidence < 0.3 and risk_score < 20:
            ml_agreement = 0.10
            
        confidence = base + evidence_bonus + ml_agreement
        return min(0.99, confidence)

# ============ HYBRID RISK SCORING ENGINE ============
class HybridRiskScoringEngine:
    """
    Hybrid scoring engine that combines ML, rule-based, and API scores.
    Does NOT modify existing detection layers - only aggregates outputs.
    """

    def __init__(self, ml_result, rule_result, threat_result):
        self.ml = ml_result or {}
        self.rule = rule_result or {}
        self.threat = threat_result or {}

    def calculate(self):
        # ML Score (0-100)
        ml_probability = self.ml.get('phishing_probability', 0.5)
        ml_score = ml_probability * 100

        # Rule-based Score (0-100) - from existing RiskScoringEngine
        rule_normalized = self.rule.get('normalized_score', 0)
        rule_score = rule_normalized

        # API Score (0-100)
        api_score = self._calculate_api_score()

        # Weighted combination
        final_score = (ml_score * 0.4) + (rule_score * 0.3) + (api_score * 0.3)
        final_score = min(100, max(0, round(final_score, 1)))

        severity = self._get_severity(final_score)

        return {
            'final_score': final_score,
            'severity': severity,
            'component_scores': {
                'ml_score': round(ml_score, 1),
                'rule_score': round(rule_score, 1),
                'api_score': round(api_score, 1)
            },
            'weights': {
                'ml': 0.4,
                'rule': 0.3,
                'api': 0.3
            }
        }

    def _calculate_api_score(self):
        score = 0
        threat_intel = self.threat or {}
        
        # DEBUG
        logger.info(f"API Score calc - threat_intel keys: {list(threat_intel.keys())}")
        
        # VirusTotal
        vt = threat_intel.get('virustotal', {})
        logger.info(f"VT checked: {vt.get('checked')}, malicious: {vt.get('malicious')}")
        if vt.get('checked'):
            malicious = vt.get('malicious', 0)
            suspicious = vt.get('suspicious', 0)
            total = malicious + suspicious + vt.get('harmless', 0) + vt.get('undetected', 0)
            if total > 0:
                score = max(score, ((malicious + suspicious) / total) * 100)
            else:
                score = max(score, 30)  # Checked but no data yet

        # Google Safe Browsing
        gsb = threat_intel.get('google_safe_browsing', {})
        logger.info(f"GSB checked: {gsb.get('checked')}, threat: {gsb.get('threat_found')}")
        if gsb.get('checked'):
            score = 100 if gsb.get('threat_found') else max(score, 20)

        # PhishTank
        pt = threat_intel.get('phishtank', {})
        if pt.get('checked'):
            score = 100 if pt.get('found') else max(score, 20)

        # Minimum score if any API responded
        if any([
            vt.get('checked'),
            gsb.get('checked'),
            pt.get('checked')
        ]):
            score = max(score, 25)
            
        logger.info(f"Final API score: {score}")
        return score

    def _get_severity(self, score):
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
        
 
        # ... rest of method

# ============ MAIN DETECTION PIPELINE ============
class PhishingDetectionPipeline:
    def __init__(self, url):
        self.url = url
        self.results = {}
        self.scan_id = str(uuid.uuid4())[:8]

    def analyze(self):
        start_time = time.time()
        logger.info(f"[{self.scan_id}] Starting analysis for: {self.url}")

        # Expand shortened URLs first
        expanded_url, was_shortened = expand_short_url(self.url)
        if was_shortened:
            self.results['url_expanded'] = {
                'original': self.url,
                'expanded': expanded_url,
                'was_shortened': True
            }

        self.parser = URLParser(expanded_url)
        self.results['url_structure'] = self.parser.get_components()

        brand_detector = BrandImpersonationDetector(self.parser)
        self.results['brand_analysis'] = brand_detector.analyze()

        anomaly_detector = StructuralAnomalyDetector(self.parser)
        self.results['structural_analysis'] = anomaly_detector.analyze()

        keyword_analyzer = KeywordContextAnalyzer(self.parser)
        self.results['keyword_analysis'] = keyword_analyzer.analyze()

        self.results['ml_prediction'] = self._get_ml_prediction()
        self.results['threat_intelligence'] = self._get_threat_intel()

        scoring_engine = RiskScoringEngine(
            self.parser,
            self.results['brand_analysis'],
            self.results['structural_analysis'],
            self.results['keyword_analysis'],
            self.results['ml_prediction'],
            self.results['threat_intelligence']
        )
        self.results['risk_assessment'] = scoring_engine.calculate()

        # Hybrid scoring
        hybrid_engine = HybridRiskScoringEngine(
            self.results['ml_prediction'],
            self.results['risk_assessment'],
            self.results['threat_intelligence']
        )
        self.results['hybrid_score'] = hybrid_engine.calculate()

        elapsed = round(time.time() - start_time, 3)
        logger.info(f"[{self.scan_id}] Analysis complete in {elapsed}s")

        return self._format_output(elapsed)

    def _get_ml_prediction(self):
        try:
            if ml_model.model:
                return ml_model.predict(self.parser.normalized_url)
        except Exception as e:
            logger.warning(f"[{self.scan_id}] ML prediction failed: {e}")
        return {'phishing_probability': 0.5, 'confidence': 0.5}

    def _get_threat_intel(self):
        result = {}
        vt_key = CONFIG.get('VIRUSTOTAL_API_KEY', '').strip()
        gsb_key = CONFIG.get('GSB_API_KEY', '').strip()
        
        # VT
        if vt_key:
            try:
                result['virustotal'] = threat_intel.check_virustotal(self.parser.normalized_url)
            except Exception as e:
                logger.error(f"[{self.scan_id}] VT error: {e}")
                result['virustotal'] = {'checked': False, 'error': str(e)}
        else:
            result['virustotal'] = {'checked': False, 'reason': 'No VT key'}
        
        # GSB
        if gsb_key:
            try:
                result['google_safe_browsing'] = threat_intel.check_google_safe_browsing(self.parser.normalized_url)
            except Exception as e:
                logger.error(f"[{self.scan_id}] GSB error: {e}")
                result['google_safe_browsing'] = {'checked': False, 'error': str(e)}
        else:
            result['google_safe_browsing'] = {'checked': False, 'reason': 'No GSB key'}
        
        # PhishTank
        try:
            result['phishtank'] = threat_intel.check_phishtank(self.parser.normalized_url)
        except Exception as e:
            logger.error(f"[{self.scan_id}] PT error: {e}")
            result['phishtank'] = {'checked': False, 'error': str(e)}
        
        return result

    def _format_output(self, elapsed_time=0):
        risk = self.results['risk_assessment']
        hybrid = self.results['hybrid_score']

        verdict = self._generate_verdict(risk, hybrid)
        recommendations = self._generate_recommendations(risk, hybrid)

        # Build method comparison
        method_comparison = self._build_method_comparison(risk, hybrid)

        return {
            'url': self.url,
            'normalized_url': self.parser.normalized_url,
            'domain_info': {
                'subdomain': self.parser.subdomain,
                'domain': self.parser.domain,
                'suffix': self.parser.suffix,
                'registered_domain': self.parser.registered_domain,
                'is_trusted': self.parser.is_trusted
            },
            'verdict': verdict,
            'risk_level': risk['risk_level'],
            'risk_score': risk['normalized_score'],
            'hybrid_score': hybrid['final_score'],
            'hybrid_severity': hybrid['severity'],
            'component_scores': hybrid['component_scores'],
            'confidence': round(risk['confidence'] * 100, 1),
            'primary_threats': risk['primary_threats'],
            'all_factors': risk['factors'],
            'method_comparison': method_comparison,
            'layered_results': {
                'brand_impersonation': self.results['brand_analysis'],
                'structural_anomalies': self.results['structural_analysis'],
                'keyword_context': self.results['keyword_analysis'],
                'ml_prediction': self.results['ml_prediction'],
                'threat_intelligence': self.results['threat_intelligence']
            },
            'recommendations': recommendations,
            'scan_metadata': {
                'scan_id': self.scan_id,
                'elapsed_time': elapsed_time,
                'timestamp': datetime.now().isoformat()
            }
        }

    def _build_method_comparison(self, risk, hybrid):
        """Build comparison of all analysis methods."""
        comparison = {
            'rule_based': {
                'score': risk['normalized_score'],
                'level': risk['risk_level'],
                'confidence': round(risk['confidence'] * 100, 1),
                'available': True
            },
            'ml_model': {
                'score': round(self.results['ml_prediction'].get('phishing_probability', 0) * 100, 1),
                'confidence': round(self.results['ml_prediction'].get('confidence', 0) * 100, 1),
                'available': ml_model.model is not None and ml_model.model_info is not None and str(ml_model.model_info.get('version', 0)).replace('.', '').isdigit() and float(ml_model.model_info.get('version', 0)) > 0
            },
            'api_threat_intel': {
                'score': hybrid.get('component_scores', {}).get('api_score', 0),
                'available': self._has_api_keys()
            }
        }

        # Determine consensus
        scores = []
        if comparison['rule_based']['available']:
            scores.append(comparison['rule_based']['score'])
        if comparison['ml_model']['available']:
            scores.append(comparison['ml_model']['score'])
        if comparison['api_threat_intel']['available'] and comparison['api_threat_intel']['score'] > 0:
            scores.append(comparison['api_threat_intel']['score'])

        if scores:
            avg_score = sum(scores) / len(scores)
            std_dev = math.sqrt(sum((s - avg_score) ** 2 for s in scores) / len(scores)) if len(scores) > 1 else 0
            comparison['consensus'] = {
                'average_score': round(avg_score, 1),
                'agreement': 'HIGH' if std_dev < 15 else 'MEDIUM' if std_dev < 30 else 'LOW',
                'methods_used': len(scores)
            }

        return comparison

    def _has_api_keys(self):
        vt_key = CONFIG.get('VIRUSTOTAL_API_KEY', '')
        gsb_key = CONFIG.get('GSB_API_KEY', '')
        return bool(vt_key.strip() or gsb_key.strip())

    def _generate_verdict(self, risk, hybrid):
        level = risk['risk_level']
        hybrid_severity = hybrid['severity']
        factors = risk['factors']

        # Use hybrid severity for final verdict if it's higher
        pass

        # Trusted domain override
        if self.parser.is_trusted and level in ['MINIMAL', 'LOW']:
            return "SAFE: Trusted domain with no significant threats detected."

        if level == 'HIGH':
            if any(f['layer'] == 'BRAND' for f in risk['primary_threats']):
                return "PHISHING DETECTED: This URL appears to be impersonating a trusted brand. Do not enter credentials."
            elif any(f['layer'] == 'THREAT_INTEL' for f in risk['primary_threats']):
                return "CONFIRMED MALICIOUS: This URL is flagged by security vendors as dangerous."
            else:
                return "HIGH RISK: Multiple suspicious indicators detected. Avoid this URL."

        elif level == 'MEDIUM':
            brand_issues = [f for f in factors if f['layer'] == 'BRAND']
            if brand_issues:
                return "SUSPICIOUS: Possible brand impersonation or misleading structure detected."
            else:
                return "SUSPICIOUS: Several unusual patterns detected. Proceed with caution."

        elif level == 'LOW':
            return "LOW RISK: Minor anomalies detected, but no clear malicious indicators."

        else:
            return "SAFE: No significant threats detected by automated analysis."

    def _generate_recommendations(self, risk, hybrid):
        recs = []
        level = risk['risk_level']

        # Use hybrid severity if higher
        if hybrid['severity'] == 'HIGH' and level != 'HIGH':
            level = 'HIGH'

        if level == 'HIGH':
            recs.append("BLOCK: Do not visit this URL")
            recs.append("Do not enter any credentials or personal information")
            recs.append("Report to security team immediately")
            for f in risk['primary_threats']:
                if f.get('brand'):
                    recs.append(f"Verify directly with {f['brand']} through official channels")

        elif level == 'MEDIUM':
            recs.append("CAUTION: Verify URL carefully before proceeding")
            recs.append("Check for HTTPS padlock icon")
            recs.append("Do not enter credentials unless certain of legitimacy")
            recs.append("Consider visiting site directly by typing known domain")

        elif level == 'LOW':
            recs.append("Standard precautions recommended")
            recs.append("Verify site appears legitimate")

        else:
            recs.append("No special action required")
            recs.append("Standard browsing security practices apply")

        return recs

# ============ BACKWARD COMPATIBILITY ============
# ============ BACKWARD COMPATIBILITY ============
def analyze_url_production(url):
    try:
        # Check cache first
        cached = get_cached_scan(url)
        if cached:
            return cached
        
        pipeline = PhishingDetectionPipeline(url)
        result = pipeline.analyze()
        
        # Build backward-compatible output
        output = {
            "result": result['risk_level'] if result['risk_level'] != 'MINIMAL' else 'Safe',
            "score": result['risk_score'],
            "hybrid_score": result.get('hybrid_score', result['risk_score']),
            "hybrid_severity": result.get('hybrid_severity', result['risk_level']),
            "component_scores": result.get('component_scores', {}),
            "confidence": result['confidence'] if result['confidence'] <= 1 else result['confidence'] / 100,
            "risk_level": result['risk_level'],
            "verdict": result['verdict'],
            "reasons": [t['description'] for t in result['primary_threats']] if result['primary_threats'] else ["No significant threats detected"],
            "recommendations": result['recommendations'],
            "ml_features": result['layered_results']['ml_prediction'].get('features', {}),
            "threat_intelligence": result['layered_results']['threat_intelligence'],
            "domain_info": result['domain_info'],
            "all_factors": result['all_factors'],
            "method_comparison": result.get('method_comparison', {}),
            "scan_metadata": result.get('scan_metadata', {})
        }
        
        # Cache the backward-compatible output
        set_cached_scan(url, output)
        
        return output
    except Exception as e:
        logger.error(f"Analysis failed for {url}: {e}", exc_info=True)
        return {
            "result": "Error",
            "score": 0,
            "hybrid_score": 0,
            "hybrid_severity": "UNKNOWN",
            "component_scores": {},
            "confidence": 0,
            "risk_level": "UNKNOWN",
            "verdict": f"Analysis failed: {str(e)}",
            "reasons": ["System error during analysis"],
            "recommendations": ["Retry analysis or contact administrator"],
            "ml_features": {},
            "threat_intelligence": {},
            "method_comparison": {},
            "scan_metadata": {}
        }

# ============ FEATURE EXTRACTION FOR TRAINING ============
def extract_features_from_url(url):
    features = {}
    try:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        features['url_length'] = len(url)
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        features['path_length'] = len(parsed.path)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_ip_address'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain) else 0

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.buzz', '.click', '.work', '.date', '.racing', '.loan', '.download', '.men', '.gdn']
        features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0

        keywords = ['login', 'verify', 'secure', 'account', 'password', 'bank', 'update', 'confirm', 'security', 'authentication', 'wallet', 'crypto', 'bitcoin']
        features['has_suspicious_keywords'] = sum(1 for kw in keywords if kw in url.lower())

        if len(url) > 0:
            prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
            features['entropy_score'] = -sum(p * math.log(p) / math.log(2) for p in prob if p > 0)
        else:
            features['entropy_score'] = 0

        subdomain = extracted.subdomain.lower()
        all_brands = [b for brands in TRUSTED_BRANDS.values() for b in brands if len(b) > 2]
        features['brand_in_subdomain'] = sum(1 for brand in all_brands if brand in subdomain)

        features['domain_age_days'] = -1

    except Exception as e:
        logger.warning(f"Feature extraction failed: {e}")
        for name in ['url_length', 'has_https', 'domain_age_days', 'has_at_symbol',
                     'subdomain_count', 'path_length', 'num_dots', 'num_hyphens',
                     'has_ip_address', 'suspicious_tld', 'brand_in_subdomain',
                     'has_suspicious_keywords', 'entropy_score']:
            features[name] = 0

    return features

# ============ MODEL VERSIONING ============
class ModelVersionManager:
    def __init__(self, models_dir):
        self.models_dir = models_dir
        self.versions = self._load_versions()

    def _load_versions(self):
        versions = []
        if os.path.exists(self.models_dir):
            for f in os.listdir(self.models_dir):
                if f.startswith('model_v') and f.endswith('.pkl'):
                    try:
                        version = int(f.replace('model_v', '').replace('.pkl', ''))
                        filepath = os.path.join(self.models_dir, f)
                        versions.append({
                            'version': version,
                            'filepath': filepath,
                            'created': datetime.fromtimestamp(os.path.getctime(filepath)).isoformat()
                        })
                    except:
                        pass
        return sorted(versions, key=lambda x: x['version'])

    def get_next_version(self):
        if not self.versions:
            return 1
        return self.versions[-1]['version'] + 1

    def get_latest_version(self):
        if not self.versions:
            return None
        return self.versions[-1]

    def get_model_path(self, version=None):
        if version is None:
            latest = self.get_latest_version()
            if latest:
                return latest['filepath']
            return None
        for v in self.versions:
            if v['version'] == version:
                return v['filepath']
        return None

    def save_model(self, model_data, accuracy, dataset_size):
        version = self.get_next_version()
        filename = f"model_v{version}.pkl"
        filepath = os.path.join(self.models_dir, filename)

        model_data['version'] = version
        model_data['accuracy'] = accuracy
        model_data['dataset_size'] = dataset_size
        model_data['saved_date'] = datetime.now().isoformat()

        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)

        # Update versions list
        self.versions = self._load_versions()

        return {
            'version': version,
            'filepath': filepath,
            'accuracy': accuracy,
            'dataset_size': dataset_size
        }

    def get_all_versions(self):
        result = []
        for v in self.versions:
            try:
                with open(v['filepath'], 'rb') as f:
                    data = pickle.load(f)
                    result.append({
                        'version': v['version'],
                        'accuracy': data.get('accuracy', 'Unknown'),
                        'dataset_size': data.get('dataset_size', 'Unknown'),
                        'training_date': data.get('training_date', 'Unknown'),
                        'saved_date': v['created']
                    })
            except:
                result.append({
                    'version': v['version'],
                    'accuracy': 'Unknown',
                    'dataset_size': 'Unknown',
                    'training_date': 'Unknown',
                    'saved_date': v['created']
                })
        return result

model_version_manager = ModelVersionManager(CONFIG['MODELS_DIR'])

# ============ MODEL TRAINER ============
class ModelTrainer:
    def __init__(self):
        self.feature_names = [
            'url_length', 'has_https', 'domain_age_days', 'has_at_symbol',
            'subdomain_count', 'path_length', 'num_dots', 'num_hyphens',
            'has_ip_address', 'suspicious_tld', 'brand_in_subdomain',
            'has_suspicious_keywords', 'entropy_score'
        ]
        self.training_status = {
            'is_training': False,
            'progress': 0,
            'message': '',
            'last_result': None
        }

    def validate_csv(self, filepath):
        try:
            df = pd.read_csv(filepath)
            required_columns = ['url', 'label']

            missing = [col for col in required_columns if col not in df.columns]
            if missing:
                return False, f"Missing columns: {', '.join(missing)}"

            if df.empty:
                return False, "CSV file is empty"

            if not df['label'].isin([0, 1]).all():
                return False, "Label column must contain only 0 (legitimate) or 1 (phishing)"

            return True, f"Valid CSV with {len(df)} rows"
        except Exception as e:
            return False, f"Error reading CSV: {str(e)}"

    def prepare_data_from_csv(self, filepath, additional_data=None):
        df = pd.read_csv(filepath)

        # Merge with additional data (corrections) if provided
        if additional_data:
            additional_df = pd.DataFrame(additional_data)
            df = pd.concat([df, additional_df], ignore_index=True)
            df = df.drop_duplicates(subset=['url'])

        data = []

        total = len(df)
        for idx, row in df.iterrows():
            features = extract_features_from_url(str(row['url']))
            features['label'] = int(row['label'])
            data.append(features)

            self.training_status['progress'] = int((idx + 1) / total * 30)
            self.training_status['message'] = f"Extracting features... {idx + 1}/{total}"

        return pd.DataFrame(data)

    def train_from_csv(self, filepath, test_size=0.2, additional_data=None):
        self.training_status['is_training'] = True
        self.training_status['progress'] = 0
        self.training_status['message'] = "Starting training..."

        try:
            is_valid, msg = self.validate_csv(filepath)
            if not is_valid:
                self.training_status['is_training'] = False
                self.training_status['message'] = msg
                return {'success': False, 'error': msg}

            self.training_status['message'] = "Loading CSV file..."
            df = self.prepare_data_from_csv(filepath, additional_data)

            legit_count = len(df[df['label'] == 0])
            phishing_count = len(df[df['label'] == 1])

            if legit_count < 10 or phishing_count < 10:
                self.training_status['is_training'] = False
                return {'success': False, 'error': f"Need at least 10 samples per class. Got {legit_count} legitimate, {phishing_count} phishing"}

            X = df[self.feature_names]
            y = df['label']

            self.training_status['progress'] = 40
            self.training_status['message'] = "Splitting dataset..."

            from sklearn.model_selection import train_test_split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )

            self.training_status['progress'] = 50
            self.training_status['message'] = "Training Random Forest model..."

            from sklearn.ensemble import RandomForestClassifier
            from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )

            model.fit(X_train, y_train)

            self.training_status['progress'] = 80
            self.training_status['message'] = "Evaluating model..."

            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)

            importance = dict(zip(self.feature_names, model.feature_importances_.tolist()))
            importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))

            model_data = {
                'model': model,
                'feature_names': self.feature_names,
                'training_date': datetime.now().isoformat(),
                'samples': len(df),
                'accuracy': accuracy,
                'class_distribution': {'legitimate': legit_count, 'phishing': phishing_count},
                'feature_importance': importance
            }

            # Save with versioning
            version_info = model_version_manager.save_model(model_data, accuracy, len(df))

            # Also save as current model for immediate use
            with open(CONFIG['ML_MODEL_PATH'], 'wb') as f:
                pickle.dump(model_data, f)

            self.training_status['progress'] = 100
            self.training_status['message'] = "Training complete!"
            self.training_status['is_training'] = False

            result = {
                'success': True,
                'accuracy': round(accuracy, 4),
                'samples': len(df),
                'legitimate': legit_count,
                'phishing': phishing_count,
                'test_samples': len(X_test),
                'feature_importance': importance,
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
                'classification_report': classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'], output_dict=True),
                'version': version_info['version']
            }

            self.training_status['last_result'] = result
            return result

        except Exception as e:
            self.training_status['is_training'] = False
            self.training_status['message'] = f"Error: {str(e)}"
            logger.error(f"Training failed: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    def get_status(self):
        return self.training_status

    def reset_status(self):
        self.training_status = {
            'is_training': False,
            'progress': 0,
            'message': '',
            'last_result': None
        }

model_trainer = ModelTrainer()

# ============ ML MODEL ============
class PhishingMLModel:
    def __init__(self):
        self.model = None
        self.feature_names = [
            'url_length', 'has_https', 'domain_age_days', 'has_at_symbol',
            'subdomain_count', 'path_length', 'num_dots', 'num_hyphens',
            'has_ip_address', 'suspicious_tld', 'brand_in_subdomain',
            'has_suspicious_keywords', 'entropy_score'
        ]
        self.model_info = None
        self.load_model()

    def load_model(self):
        try:
            if os.path.exists(CONFIG['ML_MODEL_PATH']):
                with open(CONFIG['ML_MODEL_PATH'], 'rb') as f:
                    model_data = pickle.load(f)
                    self.model = model_data['model']
                    self.feature_names = model_data.get('feature_names', self.feature_names)
                    self.model_info = {
                        'training_date': model_data.get('training_date', 'Unknown'),
                        'samples': model_data.get('samples', 'Unknown'),
                        'accuracy': model_data.get('accuracy', 'Unknown'),
                        'version': model_data.get('version', 'N/A')
                    }
                logger.info(f"Loaded trained model from {CONFIG['ML_MODEL_PATH']}")
            else:
                # Try to load latest versioned model
                latest_path = model_version_manager.get_model_path()
                if latest_path:
                    with open(latest_path, 'rb') as f:
                        model_data = pickle.load(f)
                        self.model = model_data['model']
                        self.feature_names = model_data.get('feature_names', self.feature_names)
                        self.model_info = {
                            'training_date': model_data.get('training_date', 'Unknown'),
                            'samples': model_data.get('samples', 'Unknown'),
                            'accuracy': model_data.get('accuracy', 'Unknown'),
                            'version': model_data.get('version', 'N/A')
                        }
                    # Copy to main path
                    with open(CONFIG['ML_MODEL_PATH'], 'wb') as f:
                        pickle.dump(model_data, f)
                    logger.info(f"Loaded versioned model from {latest_path}")
                else:
                    logger.warning("No trained model found. Please train a model in the admin panel.")
                    self._create_dummy_model()
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self._create_dummy_model()

    def _create_dummy_model(self):
        from sklearn.ensemble import RandomForestClassifier
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        X = np.random.rand(100, len(self.feature_names))
        y = np.random.randint(0, 2, 100)
        self.model.fit(X, y)
        self.model_info = {'training_date': 'Dummy', 'samples': 100, 'accuracy': 0.5, 'version': 0, 'is_dummy': True}

    def extract_features(self, url):
        features = {}
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)

            features['url_length'] = len(url)
            features['has_https'] = 1 if parsed.scheme == 'https' else 0
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['path_length'] = len(parsed.path)
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['has_at_symbol'] = 1 if '@' in url else 0
            features['has_ip_address'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain) else 0

            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.buzz', '.click', '.work', '.date', '.racing', '.loan', '.download', '.men', '.gdn']
            features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0

            keywords = ['login', 'verify', 'secure', 'account', 'password', 'bank', 'update', 'confirm', 'security', 'authentication', 'wallet', 'crypto', 'bitcoin']
            features['has_suspicious_keywords'] = sum(1 for kw in keywords if kw in url.lower())

            if len(url) > 0:
                prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
                features['entropy_score'] = -sum(p * math.log(p) / math.log(2) for p in prob if p > 0)
            else:
                features['entropy_score'] = 0

            brands = ['paypal', 'google', 'amazon', 'apple', 'microsoft', 'facebook', 'netflix', 'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard']
            subdomain = extracted.subdomain.lower()
            features['brand_in_subdomain'] = sum(1 for brand in brands if brand in subdomain)

            try:
                domain = f"{extracted.domain}.{extracted.suffix}"
                # Skip whois on Windows (no SIGALRM)
                if hasattr(signal, 'SIGALRM'):
                    with time_limit(CONFIG['DOMAIN_AGE_TIMEOUT']):
                        w = whois.whois(domain)
                        if w.creation_date:
                            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                            if isinstance(creation, datetime):
                                features['domain_age_days'] = (datetime.now() - creation).days
                            else:
                                features['domain_age_days'] = -1
                        else:
                            features['domain_age_days'] = -1
                else:
                    features['domain_age_days'] = -1
            except:
                features['domain_age_days'] = -1

        except Exception as e:
            logger.warning(f"Feature extraction error: {e}")
            for name in self.feature_names:
                features[name] = 0

        return [features.get(name, 0) for name in self.feature_names]

    def predict(self, url):
        try:
            features = self.extract_features(url)
            X = pd.DataFrame([features], columns=self.feature_names)
            prediction = self.model.predict(X)[0]
            probability = self.model.predict_proba(X)[0]
            is_dummy = getattr(self, 'model_info', {}).get('is_dummy', False)
            return {
                'is_phishing': bool(prediction),
                'confidence': 0.3 if is_dummy else float(max(probability)),  # Low confidence for dummy
                'phishing_probability': 0.5 if is_dummy else float(probability[1]) if len(probability) > 1 else 0.0,
                'features': dict(zip(self.feature_names, features))
            }
        except Exception as e:
            logger.warning(f"ML prediction error: {e}")
            return {
                'is_phishing': False,
                'confidence': 0.5,
                'phishing_probability': 0.5,
                'features': dict(zip(self.feature_names, features if 'features' in locals() else [0]*len(self.feature_names)))
            }

ml_model = PhishingMLModel()

# ============ THREAT INTELLIGENCE ============
class ThreatIntelligence:
    def __init__(self):
        self.phishtank_cache = []
        self.virustotal_cache = {}
        self.gsb_cache = {}
        self.last_update = None
        self.cache_duration = timedelta(hours=1)

    def check_phishtank(self, url):
        try:
            # Check cache
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            if hasattr(self, 'phishtank_cache_dict') and url_hash in self.phishtank_cache_dict:
                return self.phishtank_cache_dict[url_hash]
            
            response = requests.get(
                CONFIG['PHISHTANK_API_URL'],
                timeout=CONFIG['REQUEST_TIMEOUT']
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if url in entry.get('url', '') or entry.get('url', '') in url:
                        result = {'checked': True, 'found': True, 'phish_id': entry.get('phish_id')}
                        if not hasattr(self, 'phishtank_cache_dict'):
                            self.phishtank_cache_dict = {}
                        self.phishtank_cache_dict[url_hash] = result
                        return result
                
                result = {'checked': True, 'found': False}
                if not hasattr(self, 'phishtank_cache_dict'):
                    self.phishtank_cache_dict = {}
                self.phishtank_cache_dict[url_hash] = result
                return result
            else:
                return {'checked': False, 'status_code': response.status_code}
        except Exception as e:
            logger.warning(f"PhishTank error: {e}")
            return {'checked': False, 'error': str(e)}
        
    def check_virustotal(self, url):
        vt_key = CONFIG.get('VIRUSTOTAL_API_KEY', '').strip()
        if not vt_key:
            return {'checked': False, 'reason': 'No API key configured'}
        try:
            headers = {'x-apikey': vt_key}
            url_id = hashlib.sha256(url.encode()).hexdigest()

            # Check cache
            if url_id in self.virustotal_cache:
                cache_time, result = self.virustotal_cache[url_id]
                if datetime.now() - cache_time < self.cache_duration:
                    logger.info(f"VirusTotal cache hit for {url[:30]}...")
                    return result

            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            logger.info(f"VirusTotal checking: {url[:30]}...")
            response = requests.get(vt_url, headers=headers, timeout=CONFIG['REQUEST_TIMEOUT'])
            logger.info(f"VirusTotal response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                result = {
                    'checked': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation_score': stats.get('malicious', 0) + stats.get('suspicious', 0)
                }
                self.virustotal_cache[url_id] = (datetime.now(), result)
                logger.info(f"VirusTotal result: {result}")
                return result
            elif response.status_code == 404:
                # URL not analyzed yet — submit for analysis
                logger.info(f"VirusTotal 404 for {url[:30]}... — submitting for analysis")
                try:
                    submit_url = "https://www.virustotal.com/api/v3/urls"
                    submit_data = {"url": url}
                    submit_response = requests.post(
                        submit_url, 
                        headers=headers, 
                        data=submit_data,
                        timeout=CONFIG['REQUEST_TIMEOUT']
                    )
                    logger.info(f"VirusTotal submit status: {submit_response.status_code}")
                    if submit_response.status_code in (200, 201):
                        return {
                            'checked': True, 
                            'status_code': 404, 
                            'note': 'URL submitted to VirusTotal for analysis',
                            'submitted': True,
                            'malicious': 0, 
                            'suspicious': 0, 
                            'harmless': 0, 
                            'undetected': 0
                        }
                except Exception as submit_err:
                    logger.warning(f"VirusTotal submit failed: {submit_err}")
                
                return {
                    'checked': True, 
                    'status_code': 404, 
                    'note': 'URL not yet analyzed by VirusTotal',
                    'submitted': False,
                    'malicious': 0, 
                    'suspicious': 0, 
                    'harmless': 0, 
                    'undetected': 0
                }
            else:
                logger.warning(f"VirusTotal unexpected status: {response.status_code}")
                return {'checked': False, 'status_code': response.status_code, 'error': f'HTTP {response.status_code}'}
        except requests.exceptions.Timeout:
            logger.warning("VirusTotal check timed out")
            return {'checked': False, 'error': 'Request timeout', 'fallback': True}
        except Exception as e:
            logger.warning(f"VirusTotal error: {e}")
            return {'checked': False, 'error': str(e), 'fallback': True}

    def check_google_safe_browsing(self, url):
        gsb_key = CONFIG.get('GSB_API_KEY', '').strip()
        if not gsb_key:
            return {'checked': False, 'reason': 'No API key configured'}
        try:
            # Check cache
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            if url_hash in self.gsb_cache:
                cache_time, result = self.gsb_cache[url_hash]
                if datetime.now() - cache_time < self.cache_duration:
                    return result

            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={CONFIG['GSB_API_KEY']}"
            payload = {
                "client": {"clientId": "phishguard", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            response = requests.post(api_url, json=payload, timeout=CONFIG['REQUEST_TIMEOUT'])
            data = response.json()
            if 'matches' in data:
                result = {'checked': True, 'threat_found': True, 'threat_type': data['matches'][0]['threatType'], 'platform': data['matches'][0]['platformType']}
            else:
                result = {'checked': True, 'threat_found': False}

            self.gsb_cache[url_hash] = (datetime.now(), result)
            return result
        except requests.exceptions.Timeout:
            logger.warning("GSB check timed out")
            return {'checked': False, 'error': 'Request timeout', 'fallback': True}
        except Exception as e:
            logger.warning(f"GSB error: {e}")
            return {'checked': False, 'error': str(e), 'fallback': True}

threat_intel = ThreatIntelligence()

# ============ DATABASE INSTANCES ============
# Initialize SQLite database
sqlite_db = Database()


# ============ ROUTES ============
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    ip = request.remote_addr
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        allowed, message = check_login_lockout(ip)
        if not allowed:
            flash(message, 'danger')
            return render_template('login.html')

        # Check SQLite database first, fallback to env config
        user = sqlite_db.get_user_by_username(username)
        auth_success = False

        if user:
            # Verify with bcrypt
            try:
                auth_success = bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8'))
            except:
                auth_success = False
        else:
            # Fallback to legacy SHA256
            if username == CONFIG['ADMIN_USERNAME'] and CONFIG['ADMIN_PASSWORD_HASH']:
                try:
                    auth_success = bcrypt.checkpw(
                        password.encode(),
                        CONFIG['ADMIN_PASSWORD_HASH'].encode()
                    )
                except:
                    auth_success = False

        if auth_success:
            session['admin_logged_in'] = True
            session['last_activity'] = datetime.now().isoformat()
            record_login_attempt(ip, True)
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            record_login_attempt(ip, False)
            remaining = CONFIG['MAX_LOGIN_ATTEMPTS'] - login_attempts[ip][0]
            flash(f"Invalid credentials. {remaining} attempts remaining.", 'danger')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/admin')
@login_required
def admin_dashboard():
    stats = sqlite_db.get_stats()
    recent_scans = sqlite_db.get_recent_scans(10)
    settings = sqlite_db.get_settings()
    model_info = ml_model.model_info if ml_model.model_info else {'training_date': 'Not trained', 'samples': 0, 'accuracy': 0, 'version': 'N/A'}

    # Get chart data
    chart_data = sqlite_db.get_scan_chart_data()
    corrections = sqlite_db.get_corrections(50)
    model_versions = model_version_manager.get_all_versions()

    return render_template('admin.html', 
                         stats=stats, 
                         recent_scans=recent_scans, 
                         settings=settings, 
                         model_info=model_info,
                         chart_data=chart_data,
                         corrections=corrections,
                         model_versions=model_versions)

@app.route('/admin/api/stats')
@login_required
def api_stats():
    return jsonify(sqlite_db.get_stats())

@app.route('/admin/api/scans')
@login_required
def api_scans():
    limit = request.args.get('limit', 100, type=int)
    return jsonify(sqlite_db.get_recent_scans(limit))

@app.route('/admin/settings', methods=['POST'])
@login_required
def admin_settings():
    sqlite_db.update_settings({
        'ml_enabled': request.form.get('ml_enabled') == 'on',
        'threat_intel_enabled': request.form.get('threat_intel_enabled') == 'on',
        'auto_update': request.form.get('auto_update') == 'on',
        'notification_email': request.form.get('notification_email', '').strip()
    })
    flash('Settings saved successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/api/clear-history', methods=['POST'])
@login_required
def clear_scan_history():
    try:
        sqlite_db.clear_scans()
        # Also clear cache
        with scan_cache_lock:
            scan_cache.clear()
        flash('Scan history cleared successfully!', 'success')
        return jsonify({'success': True, 'message': 'History cleared'})
    except Exception as e:
        logger.error(f"Clear history error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/api/correction', methods=['POST'])
@login_required
def add_correction():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        corrected_label = data.get('corrected_label')

        if not url or corrected_label not in [0, 1]:
            return jsonify({'success': False, 'error': 'Invalid data'}), 400

        # Get the most recent scan for this URL to get predicted label
        scan = sqlite_db.get_scan_by_url(url)
        predicted_label = 1 if scan and scan.get('result') in ['HIGH', 'MEDIUM'] else 0

        sqlite_db.add_correction(url, predicted_label, corrected_label)

        return jsonify({'success': True, 'message': 'Correction recorded'})
    except Exception as e:
        logger.error(f"Add correction error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/api/retrain', methods=['POST'])
@login_required
def retrain_with_corrections():
    try:
        # Get all corrections
        corrections = sqlite_db.get_all_corrections()
        if not corrections:
            return jsonify({'success': False, 'error': 'No corrections available for retraining'}), 400

        # Find the latest training file
        training_files = [f for f in os.listdir(UPLOAD_FOLDER) if f.startswith('training_') and f.endswith('.csv')]
        if not training_files:
            return jsonify({'success': False, 'error': 'No original training file found'}), 400

        latest_file = sorted(training_files)[-1]
        filepath = os.path.join(UPLOAD_FOLDER, latest_file)

        # Prepare correction data
        correction_data = [{'url': c['url'], 'label': c['corrected_label']} for c in corrections]

        # Retrain
        def retrain_async():
            result = model_trainer.train_from_csv(filepath, additional_data=correction_data)
            if result['success']:
                ml_model.load_model()
                sqlite_db.mark_corrections_as_used()

        thread = threading.Thread(target=retrain_async)
        thread.start()

        return jsonify({'success': True, 'message': 'Retraining started with corrections'})
    except Exception as e:
        logger.error(f"Retrain error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/api/corrections')
@login_required
def get_corrections():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(sqlite_db.get_corrections(limit))

@app.route('/admin/api/corrections/clear', methods=['POST'])
@login_required
def clear_corrections():
    try:
        sqlite_db.clear_corrections()
        return jsonify({'success': True, 'message': 'Corrections cleared'})
    except Exception as e:
        logger.error(f"Clear corrections error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/model')
@login_required
def model_training_page():
    model_info = ml_model.model_info if ml_model.model_info else {'training_date': 'Not trained', 'samples': 0, 'accuracy': 0, 'version': 'N/A'}
    training_status = model_trainer.get_status()
    model_versions = model_version_manager.get_all_versions()
    return render_template('model_training.html', model_info=model_info, training_status=training_status, model_versions=model_versions)

@app.route('/admin/api/model/status')
@login_required
def model_status():
    model_info = ml_model.model_info if ml_model.model_info else {'training_date': 'Not trained', 'samples': 0, 'accuracy': 0, 'version': 'N/A'}
    training_status = model_trainer.get_status()
    return jsonify({'model_info': model_info, 'training_status': training_status})

@app.route('/admin/api/model/upload', methods=['POST'])
@login_required
def upload_training_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    if not file.filename.endswith('.csv'):
        return jsonify({'success': False, 'error': 'Only CSV files allowed'}), 400
    filename = secure_filename(f"training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    is_valid, msg = model_trainer.validate_csv(filepath)
    if not is_valid:
        os.remove(filepath)
        return jsonify({'success': False, 'error': msg}), 400
    def train_async():
        result = model_trainer.train_from_csv(filepath)
        ml_model.load_model()
    thread = threading.Thread(target=train_async)
    thread.start()
    return jsonify({'success': True, 'message': 'Training started', 'filename': filename})

@app.route('/admin/api/model/progress')
@login_required
def training_progress():
    return jsonify(model_trainer.get_status())

@app.route('/admin/api/model/reset', methods=['POST'])
@login_required
def reset_training_status():
    model_trainer.reset_status()
    return jsonify({'success': True})

@app.route('/admin/api/model/download-template')
@login_required
def download_template():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['url', 'label'])
    writer.writerow(['https://www.google.com', '0'])
    writer.writerow(['https://www.amazon.com', '0'])
    writer.writerow(['http://paypa1.com/login', '1'])
    writer.writerow(['https://google-verify.tk/login', '1'])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='training_template.csv'
    )

@app.route('/admin/api/model/versions')
@login_required
def get_model_versions():
    return jsonify(model_version_manager.get_all_versions())

@app.route('/admin/api/model/switch/<int:version>', methods=['POST'])
@login_required
def switch_model_version(version):
    try:
        model_path = model_version_manager.get_model_path(version)
        if not model_path:
            return jsonify({'success': False, 'error': 'Version not found'}), 404

        # Copy versioned model to main path
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)

        with open(CONFIG['ML_MODEL_PATH'], 'wb') as f:
            pickle.dump(model_data, f)

        ml_model.load_model()

        return jsonify({
            'success': True, 
            'message': f'Switched to model version {version}',
            'model_info': ml_model.model_info
        })
    except Exception as e:
        logger.error(f"Switch model error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/api/chart-data')
@login_required
def get_chart_data():
    return jsonify(sqlite_db.get_scan_chart_data())

@app.route('/scan_url', methods=['POST'])
def scan_url():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
        url = data.get('url', '').strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        
        # Validate URL length
        if len(url) > CONFIG['MAX_URL_LENGTH']:
            return jsonify({"error": f"URL too long (max {CONFIG['MAX_URL_LENGTH']} chars)"}), 400
        
        # Validate URL format
        if not re.match(r'^https?://', url, re.IGNORECASE) and not re.match(r'^[a-zA-Z0-9]', url):
            return jsonify({"error": "Invalid URL format"}), 400
        
        result = analyze_url_production(url)
        
        # Defensive check: ensure result has expected keys
        if not isinstance(result, dict):
            logger.error(f"Unexpected result type for {url}: {type(result)}")
            return jsonify({"error": "Internal analysis error"}), 500
            
        if result.get('result') != 'Error':
            scan_record = {
                'type': 'url',
                'input': url,
                'result': result.get('risk_level', 'UNKNOWN'),
                'score': result.get('score', 0),
                'confidence': result.get('confidence', 0),
                'verdict': result.get('verdict', ''),
                'reasons': result.get('reasons', [])
            }
            # Save to SQLite
            sqlite_db.add_scan(scan_record)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Scan URL error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/admin/setup', methods=['GET', 'POST'])
def admin_setup():
    """Initial setup route to create admin user with bcrypt"""
    # Check if any users exist
    if sqlite_db.get_user_count() > 0:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('setup.html')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('setup.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return render_template('setup.html')

        # Hash with bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        sqlite_db.create_user(username, password_hash)

        flash('Admin account created successfully. Please login.', 'success')
        return redirect(url_for('admin_login'))

    return render_template('setup.html')

@app.route('/admin/change-password', methods=['POST'])
@login_required
def change_password():
    try:
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('admin_dashboard'))

        if len(new_password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Get current user
        username = CONFIG['ADMIN_USERNAME']
        user = sqlite_db.get_user_by_username(username)

        if user:
            if not bcrypt.checkpw(current_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('admin_dashboard'))

            new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            sqlite_db.update_user_password(username, new_hash)
        else:
            # Fallback: check legacy hash
            current_hash = hashlib.sha256(current_password.encode()).hexdigest()
            if current_hash != CONFIG['ADMIN_PASSWORD_HASH']:
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('admin_dashboard'))

            new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            sqlite_db.create_user(username, new_hash)

        flash('Password updated successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        logger.error(f"Change password error: {e}")
        flash(f'Error updating password: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

# ============ ERROR HANDLERS ============
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(413)
def too_large(error):
    return jsonify({'error': 'File too large'}), 413

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)