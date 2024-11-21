import asyncio
from collections import deque

class AsyncPairingQueue:
    def __init__(self):
        self.givers = deque()
        self.takers = deque()

    async def give(self, giver: asyncio.Future) -> None:
        if not self.takers:
            self.givers.append(giver)
            return
        
        taker = self.takers.popleft()
        await pair(giver, taker)

    async def take(self) -> asyncio.Future:
        taker = asyncio.create_future()
        if not self.givers:
            self.takers.append(taker)
            return taker

        giver = self.givers.pop()
        await pair(giver, taker)
        return taker

async def pair(giver: asyncio.Future, taker: asyncio.Future) -> None:
    try:
        value = await giver
        await taker.set_result(value)
    except Exception as e:
        await taker.set_exception(e)

# Example usage:

queue = AsyncPairingQueue()

g1 = queue.give()
t1 = queue.take()

async def producer():
    for i in range(5):
        g2 = asyncio.create_future()
        await queue.give(g2)
        try:
            value = await g2
            print(f"Producer got {value}")
        except Exception as e:
            print(f"Error: {e}")

async def consumer():
    while True:
        t2 = queue.take()
        try:
            value = await t2
            print(f"Consumer got {value}")
        except asyncio.CancelledError:
            break

asyncio.create_task(producer())
asyncio.create_task(consumer())

try:
    await asyncio.wait({g1, t1})
except Exception as e:
    print(f"Error: {e}")

