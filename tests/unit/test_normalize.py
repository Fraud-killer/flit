"""
One spelling per identifier.

A zero-width space in an account id, a fullwidth letter in an email, an IPv4
address written as IPv6: each is a free second identity for an attacker and
nothing for a customer. Everything that keys on an identifier compares the
canonical form.
"""

import pytest

from core.normalize import (
    UnstableValue, is_mixed_script, normalize_client_id, normalize_domain,
    normalize_ip, normalize_text, skeleton,
)


class TestText:
    def test_fullwidth_and_invisible_characters_fold_away(self):
        assert normalize_text("ｕｓｅｒ​１") == "user1"
        assert normalize_text("a­b﻿c") == "abc"
        assert normalize_text("  spaced   out  ") == "spaced out"

    def test_casefold_is_optional(self):
        assert normalize_text("MiXeD") == "MiXeD"
        assert normalize_text("MiXeD", casefold=True) == "mixed"
        assert normalize_text("Straße", casefold=True) == "strasse"

    def test_it_converges(self):
        # NFKC of a composed ligature produces letters that are stable.
        assert normalize_text("ﬁle") == "file"

    def test_none_is_none(self):
        assert normalize_text(None) is None


class TestSkeleton:
    def test_lookalikes_share_a_skeleton(self):
        assert skeleton("pаypal") == skeleton("paypal")       # Cyrillic а
        assert skeleton("micr0soft") == skeleton("microsoft")
        assert skeleton("PAYPAL") == skeleton("paypal")
        assert skeleton("résumé") == skeleton("resume")

    def test_different_words_do_not(self):
        assert skeleton("paypal") != skeleton("paypa")


class TestMixedScript:
    def test_two_alphabets_in_one_word(self):
        assert is_mixed_script("pаypal") is True       # Latin + Cyrillic
        assert is_mixed_script("αpple") is True        # Greek + Latin
        assert is_mixed_script("paypal") is False
        assert is_mixed_script("москва") is False
        assert is_mixed_script("user123") is False
        assert is_mixed_script("") is False


class TestAddresses:
    def test_ipv6_forms_collapse(self):
        assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
        assert normalize_ip("::ffff:102.91.133.202") == "102.91.133.202"
        assert normalize_ip("::ffff:665b:85ca") == "102.91.133.202"
        assert normalize_ip("[2001:db8::1]") == "2001:db8::1"

    def test_not_an_address(self):
        assert normalize_ip("example.com") is None
        assert normalize_ip(None) is None

    def test_domains(self):
        assert normalize_domain("ＥＸＡＭＰＬＥ.com.") == "example.com"
        assert normalize_domain("bücher.de") == "xn--bcher-kva.de"


class TestClientIds:
    def test_invisible_characters_are_not_part_of_an_id(self):
        assert normalize_client_id("user​1") == "user1"
        assert normalize_client_id(" user1 ") == "user1"
        assert normalize_client_id("ｕｓｅｒ1") == "user1"

    def test_case_is_kept(self):
        assert normalize_client_id("User1") == "User1"


class TestEmailsAreCanonical:
    def test_fullwidth_and_zero_width_fold(self):
        from core.intelligence.email_intelligence import normalize_email

        assert normalize_email("ｐｅｎｔｅｓｔ@gmail.com") == "pentest@gmail.com"
        assert normalize_email("pen​test@gmail.com") == "pentest@gmail.com"

    def test_googlemail_is_gmail(self):
        from core.intelligence.email_intelligence import normalize_email

        assert normalize_email("a.b+x@googlemail.com") == normalize_email("ab@gmail.com")

    def test_idna_domains(self):
        from core.intelligence.email_intelligence import normalize_email

        assert normalize_email("x@bücher.de") == "x@xn--bcher-kva.de"

    def test_a_mixed_alphabet_address_is_flagged(self):
        from core.intelligence.email_intelligence import analyze

        analysis = analyze("pаypal.support@gmail.com")   # Cyrillic а
        assert analysis.is_confusable is True
        assert analysis.skeleton == "paypal.support"
        assert "confusable_spelling" in analysis.signals

        assert analyze("paypal.support@gmail.com").is_confusable is False


class TestEventsAreCanonical:
    def test_the_event_carries_one_spelling(self):
        from core.audit.events import TransactionEvent

        event = TransactionEvent(
            id="tx", type="debit", amount=1, currency_code="USD",
            client_id="user​1", ip_address="::ffff:102.91.133.202",
        )

        assert event.client_id == "user1"
        assert event.account_id == "user1"
        assert event.ip_address == "102.91.133.202"

    def test_an_invalid_address_is_left_for_verification(self):
        from core.audit.events import TransactionEvent

        event = TransactionEvent(id="tx", type="debit", amount=1, currency_code="USD",
                                 client_id="u", ip_address="not-an-ip")

        assert event.ip_address == "not-an-ip"
        assert any(error.path == "ip_address" for error in event.verify_network_attrs())

    def test_a_confusable_signup_is_flagged_by_the_rule(self, application, no_geoip):
        from tests.unit.test_decision_rules import signup

        result = signup(application, email="pаypal.support@gmail.com", client_id="conf_1")

        assert "confusable_email_spelling" in result.factors
