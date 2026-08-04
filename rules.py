"""Built-in detection rules for common secrets and API keys."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
import re
import yaml
from pathlib import Path


@dataclass
class Rule:
    """A single detection rule."""
    id: str
    description: str
    regex: str
    entropy: Optional[float] = None  # Additional entropy check if set
    severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    tags: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)  # Optional pre-filter keywords

    def __post_init__(self):
        self._compiled = re.compile(self.regex, re.IGNORECASE | re.MULTILINE)

    @property
    def pattern(self) -> re.Pattern:
        return self._compiled


# High-quality default rules inspired by Gitleaks / TruffleHog patterns
# These are carefully chosen to balance true positives vs false positives.

DEFAULT_RULES: List[Rule] = [
    # ==================== AWS ====================
    Rule(
        id="aws-access-key-id",
        description="AWS Access Key ID",
        regex=r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        severity="CRITICAL",
        tags=["aws", "cloud"],
        keywords=["AKIA", "ASIA", "AIDA"],
    ),
    Rule(
        id="aws-secret-access-key",
        description="AWS Secret Access Key",
        regex=r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        entropy=4.5,
        severity="CRITICAL",
        tags=["aws", "cloud"],
    ),
    Rule(
        id="aws-mws-key",
        description="Amazon MWS Auth Token",
        regex=r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        severity="HIGH",
        tags=["aws"],
    ),

    # ==================== GitHub ====================
    Rule(
        id="github-pat",
        description="GitHub Personal Access Token",
        regex=r"ghp_[A-Za-z0-9_]{36,}",
        severity="CRITICAL",
        tags=["github", "vcs"],
    ),
    Rule(
        id="github-oauth",
        description="GitHub OAuth Access Token",
        regex=r"gho_[A-Za-z0-9_]{36,}",
        severity="CRITICAL",
        tags=["github"],
    ),
    Rule(
        id="github-app-token",
        description="GitHub App Token",
        regex=r"(?:ghu|ghs)_[A-Za-z0-9_]{36,}",
        severity="CRITICAL",
        tags=["github"],
    ),
    Rule(
        id="github-refresh-token",
        description="GitHub Refresh Token",
        regex=r"ghr_[A-Za-z0-9_]{36,}",
        severity="HIGH",
        tags=["github"],
    ),
    Rule(
        id="github-fine-grained-pat",
        description="GitHub Fine-grained Personal Access Token",
        regex=r"github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}",
        severity="CRITICAL",
        tags=["github"],
    ),

    # ==================== Slack ====================
    Rule(
        id="slack-token",
        description="Slack Token",
        regex=r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        severity="CRITICAL",
        tags=["slack", "messaging"],
    ),
    Rule(
        id="slack-webhook",
        description="Slack Webhook URL",
        regex=r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        severity="HIGH",
        tags=["slack"],
    ),

    # ==================== Stripe ====================
    Rule(
        id="stripe-api-key",
        description="Stripe API Key",
        regex=r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",
        severity="CRITICAL",
        tags=["stripe", "payment"],
    ),

    # ==================== Google ====================
    Rule(
        id="google-api-key",
        description="Google API Key",
        regex=r"AIza[0-9A-Za-z\-_]{35}",
        severity="HIGH",
        tags=["google", "cloud"],
    ),
    Rule(
        id="google-oauth-client-secret",
        description="Google OAuth Client Secret",
        regex=r"(?i)(?:client_secret|GOOGLE_CLIENT_SECRET)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{24,})['\"]?",
        severity="HIGH",
        tags=["google"],
    ),

    # ==================== Twilio ====================
    Rule(
        id="twilio-api-key",
        description="Twilio API Key",
        regex=r"SK[0-9a-fA-F]{32}",
        severity="HIGH",
        tags=["twilio"],
    ),
    Rule(
        id="twilio-account-sid",
        description="Twilio Account SID",
        regex=r"AC[a-zA-Z0-9]{32}",
        severity="MEDIUM",
        tags=["twilio"],
    ),

    # ==================== Private Keys ====================
    Rule(
        id="rsa-private-key",
        description="RSA Private Key",
        regex=r"-----BEGIN RSA PRIVATE KEY-----",
        severity="CRITICAL",
        tags=["crypto", "private-key"],
    ),
    Rule(
        id="ssh-private-key",
        description="SSH Private Key",
        regex=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity="CRITICAL",
        tags=["crypto", "private-key", "ssh"],
    ),
    Rule(
        id="ec-private-key",
        description="EC Private Key",
        regex=r"-----BEGIN EC PRIVATE KEY-----",
        severity="CRITICAL",
        tags=["crypto", "private-key"],
    ),
    Rule(
        id="generic-private-key",
        description="Generic Private Key Header",
        regex=r"-----BEGIN PRIVATE KEY-----",
        severity="CRITICAL",
        tags=["crypto", "private-key"],
    ),
    Rule(
        id="pgp-private-key",
        description="PGP Private Key Block",
        regex=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity="CRITICAL",
        tags=["crypto", "private-key"],
    ),

    # ==================== JWT ====================
    Rule(
        id="jwt-token",
        description="JSON Web Token",
        regex=r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        severity="MEDIUM",
        tags=["jwt", "auth"],
    ),

    # ==================== Generic / High Value ====================
    Rule(
        id="generic-api-key",
        description="Generic API Key assignment",
        regex=r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
        entropy=3.5,
        severity="HIGH",
        tags=["generic"],
    ),
    Rule(
        id="generic-secret",
        description="Generic Secret assignment",
        regex=r"(?i)(?:secret|password|passwd|pwd|token)\s*[:=]\s*['\"]([^'\"]{12,})['\"]",
        entropy=3.0,
        severity="MEDIUM",
        tags=["generic"],
    ),
    Rule(
        id="heroku-api-key",
        description="Heroku API Key",
        regex=r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        severity="HIGH",
        tags=["heroku"],
        # Note: this is broad; entropy + context helps
    ),
    Rule(
        id="mailchimp-api-key",
        description="Mailchimp API Key",
        regex=r"[0-9a-f]{32}-us[0-9]{1,2}",
        severity="HIGH",
        tags=["mailchimp"],
    ),
    Rule(
        id="mailgun-api-key",
        description="Mailgun API Key",
        regex=r"key-[0-9a-zA-Z]{32}",
        severity="HIGH",
        tags=["mailgun"],
    ),
    Rule(
        id="paypal-braintree-token",
        description="PayPal Braintree Access Token",
        regex=r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        severity="CRITICAL",
        tags=["paypal", "payment"],
    ),
    Rule(
        id="square-access-token",
        description="Square Access Token",
        regex=r"sq0atp-[0-9A-Za-z\-_]{22}",
        severity="CRITICAL",
        tags=["square", "payment"],
    ),
    Rule(
        id="square-oauth-secret",
        description="Square OAuth Secret",
        regex=r"sq0csp-[0-9A-Za-z\-_]{43}",
        severity="CRITICAL",
        tags=["square"],
    ),
    Rule(
        id="telegram-bot-token",
        description="Telegram Bot Token",
        regex=r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
        severity="HIGH",
        tags=["telegram"],
    ),
    Rule(
        id="twitter-access-token",
        description="Twitter Access Token",
        regex=r"(?i)twitter.*['\"][0-9a-zA-Z]{35,44}['\"]",
        severity="HIGH",
        tags=["twitter"],
    ),
    Rule(
        id="facebook-access-token",
        description="Facebook Access Token",
        regex=r"EAACEdEose0cBA[0-9A-Za-z]+",
        severity="HIGH",
        tags=["facebook"],
    ),
    Rule(
        id="npm-token",
        description="npm Access Token",
        regex=r"npm_[A-Za-z0-9]{36}",
        severity="HIGH",
        tags=["npm", "package"],
    ),
    Rule(
        id="pypi-token",
        description="PyPI Upload Token",
        regex=r"pypi-[A-Za-z0-9_]{50,}",
        severity="HIGH",
        tags=["pypi", "package"],
    ),
]


def load_rules_from_yaml(path: Path) -> List[Rule]:
    """Load additional or custom rules from a YAML file."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    rules = []
    for item in data.get("rules", []):
        rules.append(
            Rule(
                id=item["id"],
                description=item.get("description", item["id"]),
                regex=item["regex"],
                entropy=item.get("entropy"),
                severity=item.get("severity", "HIGH").upper(),
                tags=item.get("tags", []),
                keywords=item.get("keywords", []),
            )
        )
    return rules


def get_all_rules(extra_rules_path: Optional[Path] = None) -> List[Rule]:
    """Return default rules + optional custom rules."""
    rules = list(DEFAULT_RULES)
    if extra_rules_path and extra_rules_path.exists():
        rules.extend(load_rules_from_yaml(extra_rules_path))
    return rules
