from analysis_rules import SECURITY_TOOLS
USELESS_HASHES = {"d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
KNOWN_IPS = { "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1"}
SAFE_DOMAINS = { "github.com",
    "google.com",
    "microsoft.com",
    "ubuntu.com",
    "debian.org",
    "docker.io",
    "cloudflare.com"}
SAFE_URL_KEYWORDS = ("github.com",
    "google.com",
    "microsoft.com",
    "ubuntu.com",
    "debian.org",
    "docker.io",
    "cloudflare.com")
HIGH_RISK_PROCESSES = {"bash",
    "sh",
    "curl",
    "wget",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
    "nc",
    "netcat",
    "ncat",
    "socat",
    "ssh",
    "scp"}
SAFE_PROCESSES = { "systemd",
    "cron",
    "dbus-daemon",
    "NetworkManager",
    "rsyslogd"}
SUSPICIOUS_PATHS = ("/tmp/",
    "/var/tmp/",
    "/dev/shm/")