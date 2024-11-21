import logging
from typing import List, Map

class SimpleSnapshot:
    def __init__(self, last_index: int, last_term: int):
        self.last_log_index = last_index
        self.last_log_term = last_term
        self.snapshot = []

    @property
    def snapshot(self) -> List['Log']:
        return self._snapshot

    @snapshot.setter
    def snapshot(self, value: List['Log']):
        self._snapshot = value

    def serialize(self):
        output_stream = bytearray()
        data_output_stream = BytesIO(output_stream)
        if self.snapshot:
            data_output_stream.write(len(self.snapshot).to_bytes(4, 'big'))
            for log in self.snapshot:
                output_stream.extend(log.serialize())
        else:
            data_output_stream.write(b'\x00\x00\x00\x00')

    def deserialize(self, buffer: memoryview):
        self.snapshot = []
        size = int.from_bytes(buffer[:4], 'big')
        for _ in range(size):
            try:
                log = LogParser().parse(buffer[4:])
            except UnknownLogTypeException as e:
                logging.error("Cannot recognize log", e)
            self.snapshot.append(log)

        if not self.snapshot:
            self.last_log_index, self.last_log_term = -1, -1
        else:
            self.last_log_index, self.last_log_term = self.snapshot[-1].curr_log_index, self.snapshot[-1].curr_log_term

    def get_snapshot(self) -> List['Log']:
        return self._snapshot

    def add(self, log: 'Log'):
        self.snapshot.append(log)
        self.last_log_index, self.last_log_term = log.curr_log_index, log.curr_log_term

    def __eq__(self, other):
        if not isinstance(other, SimpleSnapshot):
            return False
        return self._snapshot == other._snapshot

    def __hash__(self):
        return hash(self._snapshot)

DEFAULT_INSTALLER = SnapshotInstaller()

class Log:
    pass  # You need to implement this class in Python as well.

class RaftMember:
    pass  # You need to implement this class in Python as well.

class Logger:
    @staticmethod
    def get_logger(cls):
        return logging.getLogger(cls.__name__)

class BytesIO:
    def __init__(self, buffer: bytearray):
        self.buffer = buffer

    def write(self, data: memoryview):
        self.buffer.extend(data)

    def to_bytes(self) -> bytes:
        return bytes(self.buffer)
