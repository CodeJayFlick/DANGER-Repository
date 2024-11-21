from typing import Dict, Any

class LldbModelTargetConnector:
    def get_display(self) -> str:
        return self.get_name()

    async def set_active(self) -> None:
        pass  # CompletableFuture equivalent in Python is not implemented here

    def get_parameters(self) -> dict:
        raise NotImplementedError("getParameters method has to be implemented")

    async def launch(self, args: Dict[str, Any]) -> None:
        pass  # CompletableFuture equivalent in Python is not implemented here
