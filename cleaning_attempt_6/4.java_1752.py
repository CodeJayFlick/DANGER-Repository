import asyncio

class AsyncPlayerSendSuggestionsEvent:
    def __init__(self, player, suggestions, buffer):
        self.player = player
        self.suggestions = suggestions
        self.buffer = buffer

    @property
    def get_buffer(self):
        return self.buffer

    @property
    def get_suggestions(self):
        return self.suggestions

    def set_suggestions(self, suggestions):
        self.suggestions = suggestions

    async def is_cancelled(self):
        return self.cancelled

    async def set_cancelled(self, cancel):
        self.cancelled = cancel

    @property
    def handlers(self):
        return HandlerList()

class HandlerList:
    pass
