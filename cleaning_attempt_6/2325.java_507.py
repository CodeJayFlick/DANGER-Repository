class TraceBytesPcodeExecutorState:
    def __init__(self, trace: 'Trace', snap: int, thread: 'Thread', frame: int):
        self.trace = trace
        self.snap = snap
        self.thread = thread
        self.frame = frame

        self.viewport = DefaultTraceTimeViewport(trace)
        self.viewport.set_snap(snap)

    def with_memory_state(self) -> 'PcodeExecutorState':
        return PairedPcodeExecutorState(self, TraceMemoryStatePcodeExecutorStatePiece(self.trace, self.snap, self.thread, self.frame))

    @property
    def trace(self):
        return self._trace

    @trace.setter
    def trace(self, value: 'Trace'):
        if not isinstance(value, Trace):
            raise ValueError("Invalid type for `trace`")
        self._trace = value

    @property
    def snap(self):
        return self._snap

    @snap.setter
    def snap(self, value: int):
        self._snap = value
        self.viewport.set_snap(value)

    @property
    def thread(self):
        return self._thread

    @thread.setter
    def thread(self, value: 'Thread'):
        if not isinstance(value, Thread) or value.trace != self.trace:
            raise ValueError("Invalid type for `thread`")
        self._thread = value

    @property
    def frame(self):
        return self._frame

    @frame.setter
    def frame(self, value: int):
        self._frame = value

    def offset_to_long(self, offset: bytes) -> int:
        return Utils.bytes_to_long(offset, len(offset), self.language.is_big_endian())

    def long_to_offset(self, space: 'AddressSpace', l: int) -> bytes:
        return arithmetic.from_const(l, space.get_pointer_size())

    def set_unique(self, offset: int, size: int, val: bytes):
        assert size == len(val)
        unique.put_data(offset, val)

    def get_unique(self, offset: int, size: int) -> bytes:
        data = bytearray(size)
        unique.get_data(offset, data)
        return bytes(data)

    def get_for_space(self, space: 'AddressSpace', to_write: bool) -> 'TraceMemorySpace':
        return TraceSleighUtils.get_space_for_execution(space, self.trace, self.thread, self.frame, to_write)

    def set_in_space(self, space: 'TraceMemorySpace', offset: int, size: int, val: bytes):
        assert size == len(val)
        wrote = space.put_bytes(self.snap, space.get_address_space().get_address(offset), memorybuffer.wrap(val))
        if wrote != size:
            raise RuntimeError("Could not write full value to trace")

    def get_from_space(self, space: 'TraceMemorySpace', offset: int, size: int) -> bytes:
        buf = bytearray(size)
        read = space.get_view_bytes(self.snap, space.get_address_space().get_address(offset), memorybuffer.wrap(buf))
        if read != size:
            raise RuntimeError("Could not read full value from trace")
        return bytes(buf)

    def get_concrete_buffer(self, address: 'Address') -> 'MemBuffer':
        return self.trace.memory_manager.get_buffer_at(self.snap, address)
