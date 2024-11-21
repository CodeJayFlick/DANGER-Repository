Here is the translation of the Java code into Python:

```Python
import asyncio
from typing import Optional


class Updater:
    def __init__(self, current_release):
        self.current_release = current_release
        self.update_checker = current_release.create_update_checker()
        self.state = "NOT_STARTED"
        self.release_status = "UNKNOWN"
        self.enabled = False

    async def fetch_update_manifest(self) -> Optional[dict]:
        if not self.enabled:
            return None
        channel = self.release_channel
        if channel is None:
            raise ValueError("release channel must be specified")
        # Just check that channel name is in update name
        manifest = await self.update_checker.check(self.current_release, channel)
        return manifest

    async def check_updates(self) -> asyncio.Future[None]:
        if not self.enabled:
            future = asyncio.create_task(asyncio.sleep(0))
            return future
        # Custom releases have updating disabled
        if "selfbuilt" in self.current_release.flavor or "nightly" in self.current_release.flavor:
            self.release_status = "CUSTOM"
            future = asyncio.create_task(asyncio.sleep(0))
            return future

        self.state = "CHECKING"  # We started checking for updates
        manifest_future = self.fetch_update_manifest()
        awaitable = manifest_future.then(lambda manifest: asyncio.create_task(self.update_handler(manifest)))
        return awaitable

    async def update_handler(self, manifest):
        if manifest is not None:
            self.release_status = "OUTDATED"  # Update available
            self.update_manifest = manifest
        else:
            self.release_status = "LATEST"
        self.state = "INACTIVE"  # In any case, we finished now

    def get_current_release(self):
        return self.current_release

    def set_release_channel(self, channel):
        self.release_channel = channel

    def set_check_frequency(self, ticks):
        pass  # No equivalent in Python (no need for a separate task)

    def get_state(self):
        return self.state

    def get_release_status(self):
        return self.release_status

    async def is_update_available(self) -> bool:
        if not self.enabled:
            return False
        manifest = await self.fetch_update_manifest()
        return manifest is not None

    def set_enabled(self, enabled: bool):
        self.enabled = enabled

    def get_enabled(self) -> bool:
        return self.enabled


class ReleaseManifest:
    pass  # No equivalent in Python (no need for a separate class)


async def main():
    current_release = ReleaseManifest()
    updater = Updater(current_release)
    await updater.check_updates()


if __name__ == "__main__":
    asyncio.run(main())
```

Please note that this is not exactly the same code as the Java version. The Python code does not have direct equivalents for some of the Java classes and methods, so I had to make simplifications or omissions where necessary.