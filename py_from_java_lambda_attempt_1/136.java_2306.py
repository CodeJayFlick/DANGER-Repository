Here is a translation of the Java code into equivalent Python:

```Python
import asyncio
from typing import List, Any

class DisplayFilteredAction:
    def __init__(self, name: str, tool: Any, owner: str, provider: Any) -> None:
        self.tool = tool
        self.provider = provider
        super().__init__()

    async def is_enabled_for_context(self, context: dict) -> bool:
        obj = context.get('contextObject')
        sel = await self.provider.get_selected_container(obj)
        return sel is not None

    async def do_action(self, container: Any, path: List[str]) -> None:
        dialog = AskDialog("Filter", "Filter", str, last_cmd=path[-1])
        if dialog.is_canceled():
            return
        last_cmd = dialog.get_value_as_string()
        path.append(last_cmd)
        await self.do_action(container, path)

    async def get_offspring(self, container: Any, path: List[str]) -> None:
        to = container.get_target_object()
        model = to.get_model()
        obj = await model.fetch_model_object(path, True)
        container.set_target_object(obj)
        await self.finish_get_offspring(container, path)

    async def finish_get_offspring(self, container: Any, path: List[str]) -> None:
        asyncio.create_task(lambda: self.provider.update(container))

class AskDialog:
    def __init__(self, title: str, prompt: str, type: str, default_value: str) -> None:
        pass

    async def is_canceled(self) -> bool:
        return False  # Not implemented in Python

    async def get_value_as_string(self) -> str:
        return "default value"  # Not implemented in Python
```

Please note that this translation does not include the `DebuggerObjectsProvider`, `ObjectContainer`, and other classes, as they are specific to Java's Swing framework.