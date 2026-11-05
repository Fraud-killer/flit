"""
One spelling per identifier, before anything is compared.

Velocity, dedup and the identity ladder all ask "have we seen this before?",
and the answer is only as good as the comparison. A zero-width space in an
account id, a fullwidth letter in an email, an IPv4 address written as IPv6:
each is a free second identity for an attacker and nothing for a customer.
So every identifier is brought to one canonical form here, and compared in
that form everywhere.

Normalisation is applied until it stops changing the value, because one
pass of NFKC can produce characters a second pass folds further. If it has
not converged after a handful of passes the value is hostile by
construction and is rejected.
"""

import ipaddress
import unicodedata


MAX_PASSES = 10

# Categories with no business in an identifier: format characters (zero
# width, bidi controls, soft hyphen), private use, unassigned, and the
# surrogate range.
_STRIP_CATEGORIES = {"Cf", "Co", "Cn", "Cs"}
_STRIP_CHARS = {
    "​", "‌", "‍", "⁠", "﻿",  # zero width, word joiner, BOM
    "­",                                           # soft hyphen
    "᠎",                                           # mongolian vowel separator
}


class UnstableValue(ValueError):
    """Normalisation did not converge: the value is built to evade it."""


def _strip_invisible(value):
    return "".join(
        char for char in value
        if char not in _STRIP_CHARS and unicodedata.category(char) not in _STRIP_CATEGORIES
    )


def normalize_text(value, *, casefold=False, collapse_spaces=True):
    """NFKC, invisibles removed, trimmed; optionally case-folded."""
    if value is None:
        return None
    text = str(value)

    for _ in range(MAX_PASSES):
        folded = _strip_invisible(unicodedata.normalize("NFKC", text))
        if casefold:
            folded = folded.casefold()
        if collapse_spaces:
            folded = " ".join(folded.split())
        if folded == text:
            return text
        text = folded

    raise UnstableValue("value did not normalise")


# The letters most often used to fake a Latin one. Cyrillic and Greek
# lookalikes, fullwidth forms (already folded by NFKC), and the digits that
# pass for letters. A skeleton collapses each to its Latin look.
_CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԛ": "q", "ԝ": "w", "к": "k",
    "м": "m", "т": "t", "в": "b", "н": "h", "ғ": "f", "ԁ": "d", "ӏ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "ι": "i",
    "κ": "k", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
    # Digits and punctuation that pass for letters
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "|": "l", "!": "i", "$": "s", "@": "a",
    # Latin letters with marks lose the marks
}


def skeleton(value):
    """
    The value as it looks, not as it is encoded.

    `pаypal` with a Cyrillic а and `paypal` share a skeleton; so do
    `micr0soft` and `microsoft`. Two identifiers with the same skeleton are
    the same identifier to a human reading them, which is the whole point of
    writing one that way.
    """
    if value is None:
        return None
    text = normalize_text(value, casefold=True, collapse_spaces=False)
    out = []
    for char in text:
        char = _CONFUSABLES.get(char, char)
        # Strip combining marks: é -> e
        decomposed = unicodedata.normalize("NFD", char)
        base = "".join(c for c in decomposed if not unicodedata.combining(c))
        out.append(_CONFUSABLES.get(base, base))
    return "".join(out)


def is_mixed_script(value):
    """
    Letters from more than one script in one word: `pаypal`, half Latin,
    half Cyrillic. Legitimate names are one script.
    """
    scripts = set()
    for char in str(value or ""):
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        script = name.split(" ")[0] if name else ""
        if script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC"):
            scripts.add(script)
    return len(scripts) > 1


def normalize_domain(domain):
    """Lower-case ASCII, IDNA-encoded, trailing dot removed."""
    if not domain:
        return None
    text = normalize_text(domain, casefold=True, collapse_spaces=False).strip(".")
    if not text:
        return None
    try:
        return text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return text


def normalize_ip(value):
    """
    One spelling per address. IPv6 compressed; an IPv4 address carried
    inside IPv6 (`::ffff:1.2.3.4`) is the IPv4 address. Returns None for
    anything that is not an address.
    """
    if value is None:
        return None
    try:
        address = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def normalize_client_id(value):
    """
    A merchant's account identifier with the invisible characters removed.

    Case is kept — a merchant's ids may be case-sensitive — but a zero-width
    space is never part of one, and `user​1` and `user1` are one account.
    """
    if value is None:
        return None
    text = str(value)
    try:
        folded = normalize_text(text, collapse_spaces=False).strip()
    except UnstableValue:
        return text.strip()
    return folded or None
