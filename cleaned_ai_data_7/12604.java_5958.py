class MemoryStub:
    def __init__(self):
        self.my_memory_bytes = bytearray(8)
        self.my_memory_block = None

    def get_min_address(self):
        raise Exception("Method not implemented")

    def get_max_address(self):
        raise Exception("Method not implemented")

    def is_empty(self):
        raise Exception("Method not implemented")

    # ... (all other methods)

# Example usage:
stub = MemoryStub()
try:
    stub.get_min_address()  # This will throw an exception
except Exception as e:
    print(f"Exception: {e}")
