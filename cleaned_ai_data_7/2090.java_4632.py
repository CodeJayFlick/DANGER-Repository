import asyncio
from collections import deque

class AsyncRace:
    def __init__(self):
        self.finishers = deque()
        self.queue = deque()

    async def include(self, future: 'asyncio.Future'):
        await future
        with self.lock:
            if not self.queue:
                self.finishers.append(future.result())
            else:
                self.queue.popleft().set_result(future.result())

    @property
    def lock(self):
        return asyncio.Lock()

    async def next(self) -> 'asyncio.Future':
        await self.lock.acquire()
        try:
            if not self.finishers:
                future = asyncio.create_future()
                self.queue.append(future)
                return future
            else:
                return asyncio.wait_for(self.finishers.popleft())
        finally:
            self.lock.release()

# Example usage:

race = AsyncRace()

async def participant1():
    await asyncio.sleep(2)  # Simulate some time-consuming operation.
    return "Participant 1 finished"

async def participant2():
    await asyncio.sleep(3)  # Simulate some time-consuming operation.
    return "Participant 2 finished"

# Include participants in the race
race.include(participant1())
race.include(participant2())

# Get a future that completes with the result of the first finishing participant
future = race.next()

print(await future)
