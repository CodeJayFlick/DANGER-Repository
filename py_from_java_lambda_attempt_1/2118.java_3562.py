Here is the equivalent Python code:

```Python
import asyncio
from unittest import TestCase

class AsyncRaceTest(TestCase):
    async def test_alternate_completed(self):
        race = AsyncRace()
        await race.include(1)
        self.assertEqual(await race.next(), 1)
        await race.include(2)
        self.assertEqual(await race.next(), 2)

    async def test_two_completed(self):
        race = AsyncRace()
        await asyncio.gather(race.include(1), race.include(2))
        self.assertEqual(await race.next(), 1)
        self.assertEqual(await race.next(), 2)

    async def test_two_delayed(self):
        race = AsyncRace()
        c1 = asyncio.Future()
        c2 = asyncio.Future()
        await asyncio.gather(race.include(c1), race.include(c2))
        c1.set_result(1)
        c2.set_result(2)
        self.assertEqual(await race.next(), 1)
        self.assertEqual(await race.next(), 2)

    async def test_two_delayed_reversed(self):
        race = AsyncRace()
        c1 = asyncio.Future()
        c2 = asyncio.Future()
        await asyncio.gather(race.include(c2), race.include(c1))
        c2.set_result(2)
        c1.set_result(1)
        self.assertEqual(await race.next(), 2)
        self.assertEqual(await race.next(), 1)

class AsyncRace:
    def __init__(self):
        self.race = []

    async def include(self, value):
        if isinstance(value, asyncio.Future):
            await value
        else:
            self.race.append(value)

    async def next(self):
        return self.race.pop(0)
```

Note that Python's `asyncio` library is used to simulate asynchronous behavior. The `AsyncRaceTest` class contains four test methods, each of which tests a different scenario for the `AsyncRace` class.