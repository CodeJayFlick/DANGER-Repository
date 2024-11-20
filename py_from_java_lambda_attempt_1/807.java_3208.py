Here is a translation of the Java code into equivalent Python:

```Python
import asyncio
from typing import Dict, Any

class DbgModelTargetKernelConnectorImpl:
    def __init__(self, connectors: 'DbgModelTargetConnectorContainerImpl', name: str):
        self.connectors = connectors
        # Assuming getModel() and getManager() are implemented elsewhere in the class
        super().__init__(connectors.getModel(), connectors, name, name)
        
        param_descs = compute_parameters()
        change_attributes(param_descs)

    async def set_active(self) -> asyncio.Future:
        self.connectors.set_default_connector(self)
        return asyncio.create_future().set_result(None)

    def compute_parameters(self) -> Dict[str, Any]:
        map_ = {}
        flags = {'name': 'Flags', 'description': '0=target 1=eXDI driver'}
        options = {'name': 'Options', 'description': '-k connection options'}
        map_[flags['name']] = flags
        map_[options['name']] = options
        return map_

    def get_parameters(self) -> Dict[str, Any]:
        # Assuming TargetMethod.getParameters() is implemented elsewhere in the class
        return TargetMethod.getParameters(self)

    async def launch(self, args: Dict[str, Any]) -> asyncio.Future:
        try:
            manager = self.connectors.getModel().getManager()
            await manager.add_process()
            await manager.attach_kernel(args)
        except Exception as e:
            raise DebuggerUserException(f"Launch failed for {args}")

class DbgModelTargetConnectorContainerImpl:
    def __init__(self):
        pass

    # Assuming getModel() is implemented elsewhere in the class
    def get_model(self) -> 'DbgModel':
        return None

    def set_default_connector(self, connector: Any):
        pass

# Assuming these classes are defined elsewhere in your codebase
class DbgManager:
    async def add_process(self):
        pass

    async def attach_kernel(self, args: Dict[str, Any]):
        pass

class DebuggerUserException(Exception):
    pass

class TargetMethod:
    @staticmethod
    def getParameters(obj) -> Dict[str, Any]:
        return {}
```

Please note that this is a translation of the Java code into equivalent Python. It's not a direct copy-paste conversion and might require some adjustments to fit your specific use case.