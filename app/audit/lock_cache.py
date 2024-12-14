import asyncio


def lockcache(key=None):
    def decorator(handler):
        ikey = (
            handler.__name__
            if key is None else key
        )

        return ("%lockcache%", ikey, handler)

    return decorator


def get_runner(instance, key, handler, lock_dict, cache_dict):
    lock_dict[key] = asyncio.Lock()

    async def runner(*args, **kwargs):
        if key in cache_dict:
            return cache_dict[key]

        async with lock_dict[key]:
            if key in cache_dict:
                return cache_dict[key]

            result = await handler(instance, *args, **kwargs)
            cache_dict[key] = result

            return result

    return runner


class LockCache:
     def __new__(cls, *args, **kwargs):
        decorated = dict()

        for name, value in cls.__dict__.items():
            if not (
                isinstance(value, tuple)
                and len(value) > 0
                and value[0] == "%lockcache%"
            ):
                continue

            # TODO: Length of value must be three (3)
            # TODO: Index (1) must be dense string (key)
            # TODO: Index (2) must be a coroutine (handler)
            # TODO: Ensure index (2) is indeed instance-bound

            decorated[name] = (value[1], value[2])

        lock_dict = dict()
        cache_dict = dict()

        instance = super().__new__(cls)

        for name, (key, handler) in decorated.items():
            runner = get_runner(
                instance,
                key,
                handler,
                lock_dict,
                cache_dict,
            )

            setattr(instance, name, runner)

        return instance
