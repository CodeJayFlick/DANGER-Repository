import asyncio
from typing import Any, Dict, List

class DisplayAsAction:
    def __init__(self, name: str, tool: Any, owner: str, provider: Any) -> None:
        self.tool = tool
        self.provider = provider
        super().__init__(name, owner)

    async def is_enabled_for_context(self, context: Dict[str, Any]) -> bool:
        obj = context.get('contextObject')
        sel = await self.provider.get_selected_container(obj)
        return sel is not None

    async def do_action(self, container: Any) -> None:
        # equivalent to Java's actionPerformed method
        pass  # implement this in the subclass

    async def get_offspring(self, container: Any) -> asyncio.Future[None]:
        elements = {'elements': {}}
        attributes = {'attributes': {}}

        async with aiohttp.ClientSession() as session:
            await sequence(session).then(lambda seq: 
                (await to.fetch_elements()).update(elements)
                and (await to.fetch_attributes()).update(attributes))

        container.rebuild_containers(**elements, **attributes)

    def finish_get_offspring(self, container: Any) -> None:
        # equivalent to Java's finishGetOffspring method
        asyncio.run(asyncio.create_task(
            self.provider.update(container)))

class ObjectContainer:
    async def get_target_object(self) -> Any:
        pass  # implement this in the subclass

    async def fetch_elements(self) -> Dict[str, Any]:
        pass  # implement this in the subclass

    async def fetch_attributes(self) -> Dict[str, Any]:
        pass  # implement this in the subclass

    def rebuild_containers(self, elements: Dict[str, Any], attributes: Dict[str, Any]) -> None:
        pass  # implement this in the subclass
