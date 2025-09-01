import re
import csv
from urllib.parse import urlparse, urlunparse
import tldextract

class URLFeatureExtractor:
    WHITELIST = set()
    MAX_WHITELIST = 50000
    SUSPICIOUS_KEYWORDS = ['login', 'secure', 'account', 'bank', 'confirm', 'signin', 'money', 'free']


    @staticmethod
    def get_domain(url):
        ext = tldextract.extract(url)
        return ".".join(part for part in [ext.domain, ext.suffix] if part)


    @staticmethod
    def normalize_url(url):
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"   # normalize empty path (keeps "/" if no path given)
        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))


    @staticmethod
    def load_whitelist(csv_path):
        whitelist = set()
        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if i >= URLFeatureExtractor.MAX_WHITELIST:
                    break
                if len(row) < 2:
                    continue
                url = row[1].strip()
                if url:
                    domain = URLFeatureExtractor.get_domain(url)
                    whitelist.add(domain)
        URLFeatureExtractor.WHITELIST = whitelist

    def is_whitelisted(self):
        domain = self.domain

        # Exact match
        if domain in URLFeatureExtractor.WHITELIST:
            return True

        # Allow only the "www." variant of a whitelisted domain
        if domain.startswith("www."):
            base = domain[4:]
            if base in URLFeatureExtractor.WHITELIST:
                return True

        return False



    def __init__(self, url):
        self.url = self.normalize_url(url)    # keep full URL, normalized
        self.parsed = urlparse(self.url)         # parse full URL
        self.domain = self.get_domain(self.url)  # extract domain only
        self.path = self.parsed.path
        self.tokens_url = re.split(r'\W+', self.url)
        self.tokens_domain = re.split(r'\W+', self.domain)
        self.tokens_path = re.split(r'\W+', self.path)
        self._url_lower = self.url.lower()


    # ===== Token Stats Helper =====
    @staticmethod
    def token_stats(tokens):
        tokens = [t for t in tokens if t]
        if not tokens:
            return 0, 0, 0
        avg_len = sum(len(t) for t in tokens) / len(tokens)
        largest = max(len(t) for t in tokens)
        count = len(tokens)
        return avg_len, count, largest

    # ===== Individual Feature Methods =====
    def URL_length(self):
        return len(self.url)

    def Domain_length(self):
        return len(self.domain)

    def No_of_dots(self):
        return self.url.count('.')
    
    def hyphen_count_url(self):
        return self.url.count('-')

    # Token features
    def avg_token_length(self):
        return self.token_stats(self.tokens_url)[0]

    def token_count(self):
        return self.token_stats(self.tokens_url)[1]

    def largest_token(self):
        return self.token_stats(self.tokens_url)[2]

    def avg_domain_token_length(self):
        return self.token_stats(self.tokens_domain)[0]

    def domain_token_count(self):
        return self.token_stats(self.tokens_domain)[1]

    def largest_domain(self):
        return self.token_stats(self.tokens_domain)[2]

    def avg_path_token(self):
        return self.token_stats(self.tokens_path)[0]

    def path_token_count(self):
        return self.token_stats(self.tokens_path)[1]

    def largest_path(self):
        return self.token_stats(self.tokens_path)[2]

    # Security features
    def sec_sen_word_cnt(self):
        return sum(self._url_lower.count(word) for word in self.SUSPICIOUS_KEYWORDS)

    def IPaddress_presence(self):
        return int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', self.url)))

    def exe_in_url(self):
        return int('.exe' in self._url_lower)

    # Convenience method to extract all features in dictionary
    def extract_features(self):
        return {
            'URL_length': self.URL_length(),
            'Domain_length': self.Domain_length(),
            'No_of_dots': self.No_of_dots(),
            # 'avg_token_length': self.avg_token_length(),
            'token_count': self.token_count(),
            'largest_token': self.largest_token(),
            # 'avg_domain_token_length': self.avg_domain_token_length(),
            'domain_token_count': self.domain_token_count(),
            'largest_domain': self.largest_domain(),
            # 'avg_path_token': self.avg_path_token(),
            'path_token_count': self.path_token_count(),
            'largest_path': self.largest_path(),
            'sec_sen_word_cnt': self.sec_sen_word_cnt(),
            'IPaddress_presence': self.IPaddress_presence(),
            'exe_in_url': self.exe_in_url(),
            'hyphen_count_url': self.hyphen_count_url()
        }
