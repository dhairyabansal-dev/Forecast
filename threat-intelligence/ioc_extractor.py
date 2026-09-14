import re
from dataclasses import dataclass, field


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3",
                       "192.168.", "127.")


@dataclass
class ExtractedIOCs:
    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    md5_hashes: set[str] = field(default_factory=set)
    sha1_hashes: set[str] = field(default_factory=set)
    sha256_hashes: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "ips": sorted(self.ips),
            "domains": sorted(self.domains),
            "urls": sorted(self.urls),
            "md5_hashes": sorted(self.md5_hashes),
            "sha1_hashes": sorted(self.sha1_hashes),
            "sha256_hashes": sorted(self.sha256_hashes),
            "emails": sorted(self.emails),
        }

    def all_iocs(self) -> list[str]:
        return list(self.ips | self.domains | self.urls | self.md5_hashes | self.sha1_hashes | self.sha256_hashes)


def _is_public_ip(ip: str) -> bool:
    return not ip.startswith(PRIVATE_IP_PREFIXES)


def extract_iocs(text: str, exclude_private_ips: bool = True) -> ExtractedIOCs:
    """Extract common IOC types (IPs, domains, URLs, hashes, emails) from free text or logs."""
    iocs = ExtractedIOCs()

    ips = set(IP_PATTERN.findall(text))
    iocs.ips = {ip for ip in ips if not exclude_private_ips or _is_public_ip(ip)}

    iocs.urls = set(URL_PATTERN.findall(text))

    # Extract domains, but avoid matching things that are actually IPs or part of a URL host
    all_domains = set(DOMAIN_PATTERN.findall(text))
    iocs.domains = {d for d in all_domains if not IP_PATTERN.fullmatch(d)}

    iocs.sha256_hashes = set(SHA256_PATTERN.findall(text))
    remaining_after_sha256 = SHA256_PATTERN.sub("", text)
    iocs.sha1_hashes = set(SHA1_PATTERN.findall(remaining_after_sha256))
    remaining_after_sha1 = SHA1_PATTERN.sub("", remaining_after_sha256)
    iocs.md5_hashes = set(MD5_PATTERN.findall(remaining_after_sha1))

    iocs.emails = set(EMAIL_PATTERN.findall(text))

    return iocs


def extract_iocs_from_flow(flow: dict) -> ExtractedIOCs:
    """Extract IOCs directly from flow metadata (IPs primarily)."""
    iocs = ExtractedIOCs()
    for ip_field in ("src_ip", "dst_ip"):
        ip = flow.get(ip_field)
        if ip and _is_public_ip(ip):
            iocs.ips.add(ip)
    return iocs