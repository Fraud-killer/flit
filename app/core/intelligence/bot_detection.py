import re
import hashlib
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from django.core.cache import cache


logger = logging.getLogger(__name__)


@dataclass
class BotDetectionResult:
    is_bot: bool = False
    bot_type: Optional[str] = None
    confidence: float = 0.0
    signals: List[str] = field(default_factory=list)
    user_agent: Optional[str] = None
    fingerprint_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_bot": self.is_bot,
            "bot_type": self.bot_type,
            "confidence": self.confidence,
            "signals": self.signals,
            "user_agent": self.user_agent,
            "fingerprint_hash": self.fingerprint_hash,
        }


class BotDetector:
    KNOWN_BOT_PATTERNS = [
        (r"googlebot", "search_crawler"),
        (r"bingbot", "search_crawler"),
        (r"yandexbot", "search_crawler"),
        (r"baiduspider", "search_crawler"),
        (r"duckduckbot", "search_crawler"),
        (r"slurp", "search_crawler"),
        (r"facebookexternalhit", "social_crawler"),
        (r"twitterbot", "social_crawler"),
        (r"linkedinbot", "social_crawler"),
        (r"whatsapp", "social_crawler"),
        (r"telegrambot", "social_crawler"),
        (r"curl", "http_client"),
        (r"wget", "http_client"),
        (r"python-requests", "http_client"),
        (r"python-urllib", "http_client"),
        (r"java/", "http_client"),
        (r"apache-httpclient", "http_client"),
        (r"okhttp", "http_client"),
        (r"axios", "http_client"),
        (r"node-fetch", "http_client"),
        (r"go-http-client", "http_client"),
        (r"scrapy", "scraper"),
        (r"phantomjs", "headless_browser"),
        (r"headlesschrome", "headless_browser"),
        (r"puppeteer", "headless_browser"),
        (r"playwright", "headless_browser"),
        (r"selenium", "automation"),
        (r"webdriver", "automation"),
        (r"bot", "generic_bot"),
        (r"crawler", "generic_bot"),
        (r"spider", "generic_bot"),
        (r"scraper", "generic_bot"),
    ]

    SUSPICIOUS_UA_PATTERNS = [
        r"^$",
        r"^-$",
        r"^Mozilla/4\.0$",
        r"^Mozilla/5\.0$",
        r"^Mozilla$",
        r"^\s+$",
    ]

    HEADLESS_INDICATORS = [
        "HeadlessChrome",
        "PhantomJS",
        "Puppeteer",
        "Playwright",
        "Selenium",
    ]

    AUTOMATION_HEADERS = [
        "X-Requested-With",
        "X-Automation",
        "X-Selenium",
        "X-Puppeteer",
    ]

    @classmethod
    def detect(
        cls,
        user_agent: Optional[str],
        headers: Optional[Dict[str, str]] = None,
        fingerprint_data: Optional[Dict[str, Any]] = None,
    ) -> BotDetectionResult:
        result = BotDetectionResult(user_agent=user_agent)
        signals = []
        confidence = 0.0

        if not user_agent:
            signals.append("missing_user_agent")
            confidence += 0.4
        else:
            ua_lower = user_agent.lower()

            for pattern, bot_type in cls.KNOWN_BOT_PATTERNS:
                if re.search(pattern, ua_lower):
                    result.is_bot = True
                    result.bot_type = bot_type
                    signals.append(f"known_bot_pattern:{pattern}")
                    confidence += 0.9
                    break

            for pattern in cls.SUSPICIOUS_UA_PATTERNS:
                if re.match(pattern, user_agent):
                    signals.append("suspicious_user_agent")
                    confidence += 0.5
                    break

            for indicator in cls.HEADLESS_INDICATORS:
                if indicator.lower() in ua_lower:
                    signals.append(f"headless_indicator:{indicator}")
                    confidence += 0.7
                    result.bot_type = "headless_browser"
                    break

        if headers:
            for header in cls.AUTOMATION_HEADERS:
                if header in headers:
                    signals.append(f"automation_header:{header}")
                    confidence += 0.6

            if "Accept-Language" not in headers:
                signals.append("missing_accept_language")
                confidence += 0.2

            if "Accept-Encoding" not in headers:
                signals.append("missing_accept_encoding")
                confidence += 0.2

        if fingerprint_data:
            fp_signals = cls._analyze_fingerprint(fingerprint_data)
            signals.extend(fp_signals)
            confidence += 0.3 * len(fp_signals)

            result.fingerprint_hash = cls._hash_fingerprint(fingerprint_data)

        confidence = min(confidence, 1.0)

        if confidence >= 0.7 and not result.is_bot:
            result.is_bot = True
            result.bot_type = "suspicious_automation"

        result.confidence = confidence
        result.signals = signals

        return result

    @classmethod
    def _analyze_fingerprint(cls, fingerprint_data: Dict[str, Any]) -> List[str]:
        signals = []

        if fingerprint_data.get("webdriver"):
            signals.append("webdriver_detected")

        plugins = fingerprint_data.get("plugins", [])
        if isinstance(plugins, list) and len(plugins) == 0:
            signals.append("no_plugins")

        languages = fingerprint_data.get("languages", [])
        if isinstance(languages, list) and len(languages) == 0:
            signals.append("no_languages")

        if fingerprint_data.get("hardware_concurrency") == 0:
            signals.append("zero_hardware_concurrency")

        if fingerprint_data.get("device_memory") == 0:
            signals.append("zero_device_memory")

        screen_width = fingerprint_data.get("screen_width", 0)
        screen_height = fingerprint_data.get("screen_height", 0)
        if screen_width == 0 or screen_height == 0:
            signals.append("invalid_screen_dimensions")
        elif screen_width == 800 and screen_height == 600:
            signals.append("default_screen_dimensions")

        timezone = fingerprint_data.get("timezone")
        if timezone is None or timezone == "":
            signals.append("missing_timezone")

        canvas_hash = fingerprint_data.get("canvas_hash")
        webgl_hash = fingerprint_data.get("webgl_hash")
        if canvas_hash and webgl_hash and canvas_hash == webgl_hash:
            signals.append("identical_canvas_webgl")

        return signals

    @classmethod
    def _hash_fingerprint(cls, fingerprint_data: Dict[str, Any]) -> str:
        import json
        content = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    @classmethod
    def is_allowed_bot(cls, result: BotDetectionResult) -> bool:
        allowed_types = {"search_crawler", "social_crawler"}
        return result.is_bot and result.bot_type in allowed_types

    @classmethod
    def should_block(cls, result: BotDetectionResult, threshold: float = 0.8) -> bool:
        if cls.is_allowed_bot(result):
            return False

        return result.is_bot and result.confidence >= threshold

    @classmethod
    def should_challenge(cls, result: BotDetectionResult) -> bool:
        if cls.is_allowed_bot(result):
            return False

        return (
            result.confidence >= 0.5
            or "headless_indicator" in str(result.signals)
            or "webdriver_detected" in result.signals
        )
