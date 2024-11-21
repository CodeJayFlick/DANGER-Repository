import unittest
from typing import Range

class SemisparseByteArrayTest(unittest.TestCase):

    HELLO_WORLD = "Hello, World!".encode()
    BLOCK_SIZE = 1024

    def make_range(self, lower: int, upper: int) -> Range:
        return range(lower, upper)

    def test_singles(self):
        cache = SemisparseByteArray()
        exp = set()

        cache.put_data(0, self.HELLO_WORLD, 0, len(self.HELLO_WORLD))
        exp.clear()
        exp.update(range(len(self.HELLO_World)))
        self.assertEqual(exp, set(cache.get_initialized(0, BLOCK_SIZE)))

        exp.clear()
        exp.update(set(range(len(self.HELLO_WORLD))))
        self.assertEqual(exp, set(cache.get_uninitialized(0, len(self.HELLO_WORLD))))

        cache.put_data(BLOCK_SIZE * 2 - 1, self.HELLO_WORLD, 2, 1)
        exp.clear()
        exp.update({i for i in range(len(self.HELLO_WORLD)) if i not in [0]})
        exp.add(0)
        self.assertEqual(exp, set(cache.get_uninitialized(0, len(self.HELLO_WORLD))))

    def test_boundary(self):
        cache = SemisparseByteArray()

        cache.put_data(BLOCK_SIZE - 6, self.HELLO_WORLD)
        data = bytearray(len(self.HELLO_WORLD))
        cache.get_data(BLOCK_SIZE - 6, data)
        self.assertEqual(data.decode(), "Hello, World!")

    def test_boundary_at_signed_overflow(self):
        cache = SemisparseByteArray()

        cache.put_data(2**63-1, self.HELLO_WORLD)
        data = bytearray(len(self.HELLO_World))
        cache.get_data(2**63-1, data)
        self.assertEqual(data.decode(), "Hello, World!")

    def test_large(self):
        import random
        chunk_size = BLOCK_SIZE * 10

        rand = random.Random()
        chunk = bytearray(chunk_size)

        for i in range(chunk_size):
            chunk[i] = rand.getrandbits(8) % 256

        cache = SemisparseByteArray()

        cache.put_data(BLOCK_SIZE, self.HELLO_WORLD)
        read = bytearray(len(self.HELLO_WORLD)+chunk_size+1)
        cache.get_data(BLOCK_SIZE, read, 0, len(self.HELLO_WORLD))

        for i in range(1):
            self.assertEqual(read[i], 0)

        for i in range(chunk_size-1):
            self.assertEqual(read[1+i], chunk[i])

        for i in range(len(self.HELLO_World)):
            self.assertEqual(read[chunk_size+1+i], 0)


if __name__ == '__main__':
    unittest.main()
