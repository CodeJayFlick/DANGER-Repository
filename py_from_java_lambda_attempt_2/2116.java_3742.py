Here is the translation of the given Java code into Python:

```Python
import asyncio
from concurrent.futures import Future, ThreadPoolExecutor
from collections import defaultdict

class AsyncLazyValue:
    def __init__(self, value_provider):
        self.value_provider = value_provider
        self.future = None

    async def request(self):
        if not self.future:
            self.future = self.value_provider()
        return await self.future


class AsyncLazyMap:
    def __init__(self, map, key_value_provider):
        self.map = map
        self.key_value_provider = key_value_provider
        self.futures = defaultdict(Future)

    async def get(self, key):
        if not self.futures[key].done():
            self.futures[key] = await self.key_value_provider(key)
        return await self.futures[key]

    async def put(self, key, value):
        if not self.futures[key].done():
            self.map[key] = value
            self.futures[key].set_result(value)

# Test cases

async def test_lazy_value_ask_twice():
    calls = asyncio.Semaphore(0)
    future = Future()
    lazy = AsyncLazyValue(lambda: (calls.release(), future))
    req1 = await lazy.request()
    req2 = await lazy.request()

    assert await req1 == await req2
    assert 1 == calls.get()

async def test_lazy_map_ask_twice():
    calls = defaultdict(asyncio.Semaphore, {})
    reqs = {}
    lazy_map = AsyncLazyMap({}, lambda key: (reqs[key] = Future(), calls[key].release()))
    req1a = await lazy_map.get("One")
    req1b = await lazy_map.get("One")
    req2a = await lazy_map.get("Two")
    req2b = await lazy_map.get("Two")

    assert await req1a == await req1b
    assert await req2a == await req2b

    for key in ["One", "Two"]:
        assert 1 == calls[key].get()
    assert len(calls) == 2


async def test_lazy_map_completed_map():
    reqs = {}
    lazy_map = AsyncLazyMap({}, lambda key: (reqs[key] = Future(),))
    req1 = await lazy_map.get("One")

    assert dict() == lazy_map.map

    reqs["One"].set_result(1)
    assert 1 == await asyncio.wait_for(req1, timeout=0.5)

    assert {"One": 1} == lazy_map.map


async def test_lazy_map_put():
    reqs = {}
    lazy_map = AsyncLazyMap({}, lambda key: (reqs[key] = Future(),))
    req1 = await lazy_map.get("One")

    val1 = asyncio.Semaphore(0)
    await req1.then(lambda x: val1.release())

    assert 0 == val1.get()

    await lazy_map.put("One", 1)

    assert 1 == await asyncio.wait_for(req1, timeout=0.5)
    assert 1 == val1.get()


# Run the test cases
asyncio.run(test_lazy_value_ask_twice())
asyncio.run(test_lazy_map_ask_twice())
asyncio.run(test_lazy_map_completed_map())
asyncio.run(test_lazy_map_put())
```

This Python code is equivalent to the given Java code. It defines two classes, `AsyncLazyValue` and `AsyncLazyMap`, which are used in four test cases (`test_lazy_value_ask_twice`, `test_lazy_map_ask_twice`, `test_lazy_map_completed_map`, and `test_lazy_map_put`). The tests use Python's asyncio library to simulate asynchronous behavior.