import time
import threading

class UniversalIdGenerator:
    _generator = None
    _base_time = 0
    _instance_count = int(2**31 - 1)  # set max, so that get_next_id will trigger new time
    _session_id = 0
    _id_base = 0

    def __init__(self):
        self._session_id = (int(time.time() >> 4)) & 0xffff

    @classmethod
    def install_generator(cls, generator):
        cls._generator = generator

    @staticmethod
    def get_next_id():
        if UniversalIdGenerator._instance_count >= 32:
            UniversalIdGenerator._base_time = time.time()
            UniversalIdGenerator._id_base = (UniversalIdGenerator._base_time << 21) | (UniversalIdGenerator._session_id) << 5
            UniversalIdGenerator._instance_count = 0
        return UniversalID(UniversalIdGenerator._id_base + UniversalIdGenerator._instance_count)

    @classmethod
    def initialize(cls):
        if cls._generator is None:
            cls._generator = UniversalIdGenerator()

    @staticmethod
    class UniversalID:
        def __init__(self, value):
            self.value = value

        def get_value(self):
            return self.value


def main():
    gen1 = UniversalIdGenerator()
    gen2 = UniversalIdGenerator()
    for i in range(500):
        print(f"id = {gen1.get_next_id().get_value()} next = {hex(gen1.get_next_id().get_value())}")
        print(f"id2 = {gen2.get_next_id().get_value()} next = {hex(gen2.get_next_id().get_value())}")


if __name__ == "__main__":
    main()
