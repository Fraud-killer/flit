import asyncio


def lockcache(key=None):
    """
    Memoise an async method on the instance, once per distinct key.

    `key` is a string, or a callable given the method's own arguments that
    returns the cache key for that call. Two calls that compute the same key
    share one result and one lock; different keys are independent.
    """
    def decorator(handler):
        ikey = (
            handler.__name__
            if key is None else key
        )

        return ("%lockcache%", ikey, handler)

    return decorator


def get_runner(instance, name, key, handler, lock_dict, cache_dict):
    async def runner(*args, **kwargs):
        # Namespaced by method so two methods keyed on the same value (a
        # visit id, say) never read each other's result.
        ckey = (name, key(*args, **kwargs) if callable(key) else key)

        if ckey in cache_dict:
            return cache_dict[ckey]

        lock = lock_dict.setdefault(ckey, asyncio.Lock())

        async with lock:
            if ckey in cache_dict:
                return cache_dict[ckey]

            result = await handler(instance, *args, **kwargs)
            cache_dict[ckey] = result

            return result

    return runner


class LockCache:
     def __new__(cls, *args, **kwargs):
        decorated = dict()

        for klass in cls.__mro__:
            for name, value in vars(klass).items():
                if name in decorated:
                    continue
                if not (
                    isinstance(value, tuple)
                    and len(value) == 3
                    and value[0] == "%lockcache%"
                ):
                    continue

                decorated[name] = (value[1], value[2])

        lock_dict = dict()
        cache_dict = dict()

        instance = super().__new__(cls)

        for name, (key, handler) in decorated.items():
            runner = get_runner(
                instance,
                name,
                key,
                handler,
                lock_dict,
                cache_dict,
            )

            setattr(instance, name, runner)

        return instance
