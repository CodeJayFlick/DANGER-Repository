Here is a translation of the Java code into equivalent Python code:

```Python
import asyncio
from typing import List, Dict, Any

class PeerListViewModel:
    def __init__(self):
        self.application = None  # WalletApplication instance
        self.blockchain_service = None  # BlockchainServiceLiveData instance
        self.peers = MediatorLiveData()  # MediatorLiveData<Peer> instance
        self.hostnames = HostnamesLiveData()

    async def maybe_refresh_peers(self) -> None:
        blockchain_service = await self.get_blockchain_service()
        if blockchain_service is not None:
            peers_value = blockchain_service.get_connected_peers()
            self.peers.set_value(peers_value)

    async def get_blockchain_service(self) -> Any:
        return self.blockchain_service

    @property
    def hostnames(self):
        if self.hostnames is None:
            self.hostnames = HostnamesLiveData()
        return self.hostnames


class MediatorLiveData:
    def __init__(self):
        self.value = None  # type: List[Peer]

    async def set_value(self, value) -> None:
        self.value = value

    async def add_source(self, source, callback) -> None:
        await asyncio.create_task(callback(source))


class HostnamesLiveData:
    def __init__(self):
        self.value = {}  # type: Dict[InetAddress, str]
        self.handler = asyncio.get_event_loop()

    async def reverse_lookup(self, address) -> None:
        hostnames = self.value
        if not hostnames.get(address):  # containsKey in Java equivalent
            await self.handler.run_in_executor(None, lambda: 
                hostnames[address] = str(address.canonical_name())
            )
```

Note that Python does not have direct equivalents for some of the Java classes and methods used here. For example:

- `AndroidViewModel` is replaced with a simple class.
- `AsyncTask.execute()` is replaced with `asyncio.create_task()`.
- `Handler.post()` is replaced with `self.handler.run_in_executor(None, lambda: ...)`.

Also note that Python does not have built-in support for Java's generics system.