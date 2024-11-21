class AbstractNioChannel:
    def __init__(self, handler: 'ChannelHandler', channel):
        self.handler = handler
        self.channel = channel
        self.channel_to_pending_writes = {}

    def set_reactor(self, reactor):
        self.reactor = reactor

    @property
    def java_channel(self):
        return self.channel

    def get_interested_ops(self) -> int:
        raise NotImplementedError("Must be implemented by subclass")

    def bind(self) -> None:
        raise NotImplementedError("Must be implemented by subclass")

    def read(self, key: 'SelectionKey') -> object:
        raise NotImplementedError("Must be implemented by subclass")

    @property
    def handler(self):
        return self._handler

    def flush(self, key: 'SelectionKey'):
        pending_writes = self.channel_to_pending_writes.get(key.channel())
        while (pending_write := next((p for p in pending_writes if p is not None), None)) is not None:
            try:
                do_write(pending_write, key)
            except Exception as e:
                print(f"Error writing: {e}")
        self.reactor.change_ops(key, SelectionKey.OP_READ)

    def write(self, data: object, key: 'SelectionKey'):
        if pending_writes := self.channel_to_pending_writes.get(key.channel()):
            if not pending_writes:
                synchronized(self.channel_to_pending_writes):
                    if (pending_writes := self.channel_to_pending_writes.get(key.channel())) is None:
                        pending_writes = []
                        self.channel_to_pending_writes[key.channel()] = pending_writes
            pending_writes.append(data)
        else:
            self.reactor.change_ops(key, SelectionKey.OP_WRITE)

    def do_write(self, data: object, key: 'SelectionKey'):
        raise NotImplementedError("Must be implemented by subclass")

class ChannelHandler:
    pass

class NioReactor:
    def change_ops(self, key: 'SelectionKey', ops):
        raise NotImplementedError("Must be implemented by subclass")
