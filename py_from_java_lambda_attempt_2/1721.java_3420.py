Here is the translation of the given Java code into equivalent Python:

```Python
import asyncio
from typing import Dict, Any

class LldbModelTargetProcessLaunchWithOptionsConnectorImpl:
    def __init__(self, connectors: 'LldbModelTargetConnectorContainerImpl', name: str):
        self.connectors = connectors
        # Initialize other attributes as needed

    async def set_active(self) -> asyncio.Future[None]:
        await self.connectors.set_default_connector(self)
        return asyncio.create_future()

    def compute_parameters(self) -> Dict[str, Any]:
        parameters_map = {}
        
        p0 = {'name': 'File', 'type': str, 'required': True}
        map.put('File', p0)

        # Add more parameters as needed

        return parameters_map

    async def get_parameters(self) -> asyncio.Future[Dict[str, Any]]:
        await self.connectors.get_parameters()
        return {}

    async def launch(self, args: Dict[str, Any]) -> asyncio.Future[None]:
        try:
            await self.connectors.launch(args)
        except Exception as e:
            raise DebuggerUserException(f"Launch failed for {args}") from e

class LldbModelTargetConnectorContainerImpl:
    # Implement the necessary methods
```

Please note that this is a direct translation of Java code into Python, and it might not be exactly equivalent. The provided code seems to be part of an IDE or a plugin, so you may need to adjust some parts according to your specific use case.

Also, please note that in Python, we don't have the concept of `@Override` as in Java because method overriding is handled by inheritance and polymorphism.