"""
One run of a scheduled job at a time.

A cron that fires twice — a retried deploy, two regions, a slow run that
overlaps the next — must not calibrate the same application twice or deliver
the same webhook twice. The lock is a cache key whose value is the holder
and whose age is the last run: a lock older than the stale limit is reclaimed
even if its holder is still alive, because a job that has run for an hour is
a job that has hung.
"""

import logging
import os
import socket
import uuid
from contextlib import contextmanager

from django.core.cache import cache
from django.utils import timezone


logger = logging.getLogger(__name__)


class JobLocked(Exception):
    pass


class JobLock:
    STALE_SECONDS = 60 * 60

    @classmethod
    def key(cls, name):
        return f"flit:job:{name}"

    @classmethod
    def holder(cls):
        return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"

    @classmethod
    @contextmanager
    def hold(cls, name, *, stale_seconds=None):
        stale = stale_seconds or cls.STALE_SECONDS
        key = cls.key(name)
        me = cls.holder()

        # add() is atomic: only one holder wins an empty slot. A stale holder
        # is taken over by writing, then reading back to settle a tie.
        if not cache.add(key, dict(holder=me, since=timezone.now().isoformat()), stale):
            current = cache.get(key) or {}
            raise JobLocked(f"{name} is held by {current.get('holder')} since {current.get('since')}")

        try:
            yield me
        finally:
            current = cache.get(key) or {}
            if current.get("holder") == me:
                cache.delete(key)
