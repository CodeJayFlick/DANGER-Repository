import asyncio

class NoUpdateChecker:
    async def check(self, manifest: dict, channel: str) -> dict or None:
        return await asyncio.create_task(async_return_none())

def async_return_none():
    import asyncio
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(asyncio.sleep(0))  # sleep for no time

# Example usage:
manifest = {"key": "value"}
channel = "my_channel"
checker = NoUpdateChecker()
result = checker.check(manifest, channel)
print(result)  # prints None
