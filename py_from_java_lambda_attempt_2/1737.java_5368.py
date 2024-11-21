Here is a translation of the Java code into equivalent Python:

```Python
import asyncio
from typing import Dict, Any

class LldbModelTargetTraceOrDumpConnectorImpl:
    def __init__(self, connectors: 'LldbModelTargetConnectorContainerImpl', name: str):
        self.connectors = connectors
        # Assuming getDisplay() and computeParameters() are implemented elsewhere in the class
        self.param_descs = TargetParameterMap.copyOf(self.compute_parameters())

    async def set_active(self) -> asyncio.Future:
        await self.connectors.set_default_connector(self)
        return asyncio.futures.FinishedFuture(None)

    def compute_parameters(self) -> Dict[str, Any]:
        map_ = {}
        p1 = {'name': 'TraceOrDump', 'type': str, 'description': "File", 'help': "trace or dump to be loaded"}
        map_[p1['name']] = p1
        return map_

    def get_parameters(self) -> Dict[str, Any]:
        # Assuming TargetMethod.getParameters() is implemented elsewhere in the class
        return self.connectors.get_parameters()

    async def launch(self, args: Dict[str, Any]) -> asyncio.Future:
        try:
            await self.connectors.open_file(args)
        except Exception as e:
            raise DebuggerUserException(f"Launch failed for {args}: {str(e)}")
```

Please note that Python does not have direct equivalent of Java's `CompletableFuture` and `AsyncUtils`. Instead, we use the built-in support for asynchronous programming using coroutines (async/await) or tasks.