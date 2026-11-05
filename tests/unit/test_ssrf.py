"""
FLIT connects only to what it was meant to connect to.

A visit id in a URL path, an email's domain in an RDAP lookup, a webhook URL
a merchant typed: each is somebody else's string ending up in a request FLIT
makes. The guard refuses private, loopback, link-local, carrier-NAT and
reserved addresses in every spelling, and refuses them again at connection
time, so a name that resolves one way for the check and another for the
dial gains nothing.
"""

import asyncio

import pytest

from core.outbound import BlockedAddressError, GuardedResolver, check_url, is_blocked_address


BLOCKED = [
    "127.0.0.1", "127.8.8.8", "::1",
    "10.0.0.1", "172.16.5.5", "172.31.255.255", "192.168.1.1",
    "169.254.169.254",              # cloud metadata
    "100.64.0.1", "100.127.255.254", # carrier NAT, metadata on some clouds
    "0.0.0.0", "::",
    "224.0.0.1", "ff02::1",
    "fe80::1", "fc00::1", "fd12:3456::1",
    "192.0.0.1", "198.18.0.1",
    # IPv4 hidden inside IPv6
    "::ffff:169.254.169.254", "::ffff:a9fe:a9fe", "0:0:0:0:0:ffff:a9fe:a9fe",
    "::ffff:10.0.0.1", "::ffff:7f00:1",
    "64:ff9b::a9fe:a9fe",            # NAT64
    "2002:a9fe:a9fe::",              # 6to4
    "not an address", "", "example.com",
]

ALLOWED = [
    "8.8.8.8", "1.1.1.1", "104.16.0.1", "2606:4700::1111", "::ffff:8.8.8.8",
    "172.32.0.1", "100.128.0.1", "192.169.0.1",
]


class TestBlockedAddresses:
    @pytest.mark.parametrize("address", BLOCKED)
    def test_blocked(self, address):
        assert is_blocked_address(address) is True

    @pytest.mark.parametrize("address", ALLOWED)
    def test_allowed(self, address):
        assert is_blocked_address(address) is False

    def test_loopback_can_be_allowed_for_local_development(self):
        assert is_blocked_address("127.0.0.1", allow_loopback=True) is False
        assert is_blocked_address("::1", allow_loopback=True) is False
        # but only loopback
        assert is_blocked_address("10.0.0.1", allow_loopback=True) is True


class TestUrls:
    def test_https_to_a_name_passes(self):
        assert check_url("https://api.fpjs.io/events/abc") == "api.fpjs.io"

    def test_http_is_refused_unless_asked(self):
        with pytest.raises(BlockedAddressError):
            check_url("http://example.com/")
        assert check_url("http://example.com/", allow_http=True) == "example.com"

    @pytest.mark.parametrize("url", [
        "https://user:pass@example.com/",
        "https://user@example.com/",
        "ftp://example.com/",
        "file:///etc/passwd",
        "https:///path",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::ffff:169.254.169.254]/",
        "https://127.0.0.1:8000/",
        "https://[::1]/",
        "https://10.0.0.5/admin",
    ])
    def test_refused(self, url):
        with pytest.raises(BlockedAddressError):
            check_url(url)

    def test_a_public_ip_literal_passes(self):
        assert check_url("https://8.8.8.8/") == "8.8.8.8"


class FakeResolver:
    """Answers in the order given, one list per call."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = 0

    async def resolve(self, host, port=0, family=0):
        self.calls += 1
        addresses = self.answers.pop(0) if self.answers else []
        return [dict(hostname=host, host=a, port=port, family=family, proto=0, flags=0) for a in addresses]

    async def close(self):
        pass


class TestGuardedResolver:
    def resolve(self, resolver, host="example.com"):
        return asyncio.run(resolver.resolve(host, 443))

    def test_a_public_answer_passes_through(self):
        resolver = GuardedResolver(FakeResolver(["93.184.216.34"]))
        answers = self.resolve(resolver)
        assert [a["host"] for a in answers] == ["93.184.216.34"]

    def test_a_private_answer_is_refused(self):
        resolver = GuardedResolver(FakeResolver(["10.0.0.1"]))
        with pytest.raises(BlockedAddressError):
            self.resolve(resolver)

    def test_one_private_answer_among_public_ones_refuses_the_name(self):
        """A name that is partly private is a name somebody is playing with."""
        resolver = GuardedResolver(FakeResolver(["93.184.216.34", "169.254.169.254"]))
        with pytest.raises(BlockedAddressError):
            self.resolve(resolver)

    def test_a_mapped_ipv4_answer_is_refused(self):
        resolver = GuardedResolver(FakeResolver(["::ffff:a9fe:a9fe"]))
        with pytest.raises(BlockedAddressError):
            self.resolve(resolver)

    def test_no_answer_is_refused(self):
        resolver = GuardedResolver(FakeResolver([]))
        with pytest.raises(BlockedAddressError):
            self.resolve(resolver)

    def test_rebinding_is_caught_on_the_second_resolution(self):
        """
        Public for the check, private for the connect. Every connection
        resolves through the guard, so the second answer is judged too.
        """
        resolver = GuardedResolver(FakeResolver(["93.184.216.34"], ["10.0.0.1"]))
        self.resolve(resolver)
        with pytest.raises(BlockedAddressError):
            self.resolve(resolver)


class TestFetchJson:
    def run(self, coro):
        return asyncio.run(coro)

    def test_a_blocked_url_makes_no_request(self):
        from unittest.mock import patch
        from core.outbound import fetch_json

        with patch("aiohttp.ClientSession") as session:
            result = self.run(fetch_json("https://169.254.169.254/latest/meta-data/"))

        assert result is None
        session.assert_not_called()

    def test_http_is_refused_by_default(self):
        from unittest.mock import patch
        from core.outbound import fetch_json

        with patch("aiohttp.ClientSession") as session:
            assert self.run(fetch_json("http://example.com/")) is None

        session.assert_not_called()

    def test_a_name_that_resolves_privately_yields_nothing(self):
        from unittest.mock import patch
        from core.outbound import client

        fake = FakeResolver(["10.0.0.1"])
        with patch.object(client, "GuardedResolver", lambda **kw: GuardedResolver(fake, **kw)):
            assert self.run(client.fetch_json("https://internal.example/")) is None

        assert fake.calls == 1


class TestVisitIdsAreOpaque:
    """A merchant-supplied visit id cannot change which URL FLIT fetches."""

    @pytest.mark.parametrize("request_id", [
        "../../admin", "abc/def", "abc?x=1", "abc#frag", "a b", "", None, 5,
        "x" * 129, "abc\n", "абв",
    ])
    def test_refused_without_a_request(self, request_id):
        from unittest.mock import AsyncMock, patch
        from core.services.fingerprint import FetchVisitData

        assert FetchVisitData.valid_request_id(request_id) is False

        with patch.object(FetchVisitData, "async_make_request", AsyncMock()) as make:
            assert asyncio.run(FetchVisitData.async_call(request_id)) is None

        make.assert_not_called()

    @pytest.mark.parametrize("request_id", [
        "1234567890.AbCdEf", "req_abc-123", "x" * 128,
    ])
    def test_accepted(self, request_id):
        from core.services.fingerprint import FetchVisitData

        assert FetchVisitData.valid_request_id(request_id) is True
