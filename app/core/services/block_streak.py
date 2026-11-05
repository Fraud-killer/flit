"""
How many times in a row FLIT has just said no to this origin.

A block is a message to the attacker: that variation failed. A loop reads it
and tries the next one, and each attempt is scored on its own as if the
previous ten had not happened. The streak is the memory the per-event score
lacks: an origin that has been blocked three times running is not a customer
having a bad day, and the next event from it starts from that.

Any decision that is not a block ends the streak; the day's total does not
decay until the day does. Both are kept in the cache, because they are hot,
short-lived and recomputable from the audit log if the cache is lost.
"""

from django.core.cache import cache


class BlockStreak:
    WINDOW_SECONDS = 24 * 60 * 60

    @classmethod
    def origin_for(cls, *, device_fingerprint=None, ip_address=None, client_id=None):
        from core.models import Case
        return Case.campaign_key_for(
            device_fingerprint=device_fingerprint, ip_address=ip_address, client_id=client_id,
        )

    @classmethod
    def keys(cls, application_id, origin):
        base = f"flit:streak:{application_id}:{origin}"
        return f"{base}:consecutive", f"{base}:total"

    @classmethod
    def read(cls, application_id, origin):
        if not origin:
            return dict(consecutive=0, total_24h=0)
        consecutive_key, total_key = cls.keys(application_id, origin)
        return dict(
            consecutive=int(cache.get(consecutive_key) or 0),
            total_24h=int(cache.get(total_key) or 0),
        )

    @classmethod
    def record(cls, application_id, origin, blocked):
        """Note one decision; returns the streak after it."""
        if not origin:
            return dict(consecutive=0, total_24h=0)

        consecutive_key, total_key = cls.keys(application_id, origin)

        if blocked:
            consecutive = int(cache.get(consecutive_key) or 0) + 1
            total = int(cache.get(total_key) or 0) + 1
            cache.set(consecutive_key, consecutive, cls.WINDOW_SECONDS)
            cache.set(total_key, total, cls.WINDOW_SECONDS)
        else:
            consecutive = 0
            total = int(cache.get(total_key) or 0)
            cache.delete(consecutive_key)

        return dict(consecutive=consecutive, total_24h=total)

    @classmethod
    def reset(cls, application_id, origin):
        consecutive_key, total_key = cls.keys(application_id, origin)
        cache.delete_many([consecutive_key, total_key])
