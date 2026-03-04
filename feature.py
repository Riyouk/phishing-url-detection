import ipaddress
import re
import socket
import requests
from bs4 import BeautifulSoup
from googlesearch import search
import whois
from datetime import date
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse


class FeatureExtraction:

    def __init__(self, url):
        self.url = url.strip()
        self.features = []

        self.domain = ""
        self.urlparse = None
        self.response = None
        self.soup = None
        self.whois_response = None

        # ---------------------------
        # URL Parsing
        # ---------------------------
        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
        except:
            self.domain = ""

        # ---------------------------
        # HTTP Request
        # ---------------------------
        try:
            self.response = requests.get(self.url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        except:
            self.response = None
            self.soup = None

        # ---------------------------
        # WHOIS Lookup
        # ---------------------------
        try:
            if self.domain:
                self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None

        # ---------------------------
        # Feature Extraction (30)
        # ---------------------------
        self.features = [
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbol(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.HTTPS(),
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.RequestURL(),
            self.AnchorURL(),
            self.LinksInScriptTags(),
            self.ServerFormHandler(),
            self.InfoEmail(),
            self.AbnormalURL(),
            self.WebsiteForwarding(),
            self.StatusBarCust(),
            self.DisableRightClick(),
            self.UsingPopupWindow(),
            self.IframeRedirection(),
            self.AgeofDomain(),
            self.DNSRecording(),
            self.WebsiteTraffic(),
            self.PageRank(),
            self.GoogleIndex(),
            self.LinksPointingToPage(),
            self.StatsReport()
        ]

    # ---------------------------------
    # Helper
    # ---------------------------------
    def parse_date(self, d):
        if isinstance(d, list):
            d = d[0]
        if isinstance(d, str):
            d = date_parse(d)
        return d

    # 1
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except:
            return 1

    # 2
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif len(self.url) <= 75:
            return 0
        return -1

    # 3
    def shortUrl(self):
        if re.search(r"bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly", self.url):
            return -1
        return 1

    # 4
    def symbol(self):
        return -1 if "@" in self.url else 1

    # 5
    def redirecting(self):
        return -1 if self.url.rfind("//") > 6 else 1

    # 6
    def prefixSuffix(self):
        return -1 if "-" in self.domain else 1

    # 7
    def SubDomains(self):
        dots = self.domain.count(".")
        if dots == 1:
            return 1
        elif dots == 2:
            return 0
        return -1

    # 8
    def HTTPS(self):
        return 1 if self.urlparse and self.urlparse.scheme == "https" else -1

    # 9
    def DomainRegLen(self):
        try:
            exp = self.parse_date(self.whois_response.expiration_date)
            crt = self.parse_date(self.whois_response.creation_date)
            age = (exp.year - crt.year) * 12 + (exp.month - crt.month)
            return 1 if age >= 12 else -1
        except:
            return -1

    # 10
    def Favicon(self):
        try:
            if not self.soup:
                return -1
            for link in self.soup.find_all("link", href=True):
                if self.domain in link["href"]:
                    return 1
            return -1
        except:
            return -1

    # 11
    def NonStdPort(self):
        return -1 if ":" in self.domain else 1

    # 12
    def HTTPSDomainURL(self):
        return -1 if "https" in self.domain else 1

    # 13
    def RequestURL(self):
        try:
            if not self.soup:
                return -1
            success, total = 0, 0
            for tag in self.soup.find_all(["img", "audio", "embed", "iframe"], src=True):
                total += 1
                if self.domain in tag["src"]:
                    success += 1
            if total == 0:
                return 1
            percentage = (success / total) * 100
            if percentage < 22:
                return 1
            elif percentage < 61:
                return 0
            return -1
        except:
            return -1

    # 14
    def AnchorURL(self):
        try:
            if not self.soup:
                return -1
            unsafe, total = 0, 0
            for a in self.soup.find_all("a", href=True):
                total += 1
                if "#" in a["href"] or "javascript" in a["href"].lower() or "mailto" in a["href"].lower():
                    unsafe += 1
            if total == 0:
                return 1
            percentage = (unsafe / total) * 100
            if percentage < 31:
                return 1
            elif percentage < 67:
                return 0
            return -1
        except:
            return -1

    # 15
    def LinksInScriptTags(self):
        try:
            if not self.soup:
                return -1
            success, total = 0, 0
            for tag in self.soup.find_all(["link", "script"], src=True):
                total += 1
                if self.domain in tag["src"]:
                    success += 1
            if total == 0:
                return 1
            percentage = (success / total) * 100
            if percentage < 17:
                return 1
            elif percentage < 81:
                return 0
            return -1
        except:
            return -1

    # 16
    def ServerFormHandler(self):
        try:
            if not self.soup:
                return -1
            forms = self.soup.find_all("form", action=True)
            if len(forms) == 0:
                return 1
            for form in forms:
                if form["action"] in ["", "about:blank"]:
                    return -1
                if self.domain not in form["action"]:
                    return 0
            return 1
        except:
            return -1

    # 17
    def InfoEmail(self):
        try:
            if not self.response:
                return -1
            return -1 if re.search(r"mailto:", self.response.text) else 1
        except:
            return -1

    # 18
    def AbnormalURL(self):
        try:
            return 1 if self.domain in str(self.whois_response.domain_name) else -1
        except:
            return -1

    # 19
    def WebsiteForwarding(self):
        try:
            if not self.response:
                return -1
            redirects = len(self.response.history)
            if redirects <= 1:
                return 1
            elif redirects <= 4:
                return 0
            return -1
        except:
            return -1

    # 20
    def StatusBarCust(self):
        try:
            return 1 if self.response and re.search("onmouseover", self.response.text) else -1
        except:
            return -1

    # 21
    def DisableRightClick(self):
        try:
            return 1 if self.response and re.search("event.button", self.response.text) else -1
        except:
            return -1

    # 22
    def UsingPopupWindow(self):
        try:
            return 1 if self.response and "alert(" in self.response.text else -1
        except:
            return -1

    # 23
    def IframeRedirection(self):
        try:
            return 1 if self.response and "<iframe" in self.response.text else -1
        except:
            return -1

    # 24
    def AgeofDomain(self):
        try:
            crt = self.parse_date(self.whois_response.creation_date)
            age = (date.today().year - crt.year) * 12
            return 1 if age >= 6 else -1
        except:
            return -1

    # 25
    def DNSRecording(self):
        return self.AgeofDomain()

    # 26
    def WebsiteTraffic(self):
        return 0

    # 27
    def PageRank(self):
        return 0

    # 28
    def GoogleIndex(self):
        try:
            results = list(search("site:" + self.domain, 5))
            return 1 if results else -1
        except:
            return 0

    # 29
    def LinksPointingToPage(self):
        try:
            if not self.response:
                return -1
            count = len(re.findall("<a href=", self.response.text))
            if count == 0:
                return 1
            elif count <= 2:
                return 0
            return -1
        except:
            return -1

    # 30
    def StatsReport(self):
        try:
            socket.gethostbyname(self.domain)
            if re.search(r"at\.ua|usa\.cc|bit\.ly", self.url):
                return -1
            return 1
        except:
            return 1

    def getFeaturesList(self):
        return self.features