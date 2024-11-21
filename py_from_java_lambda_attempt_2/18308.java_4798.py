Here is the translation of the Java code into Python:

```Python
class Murmur128Hash:
    def __init__(self):
        pass

    @staticmethod
    def hash(value1: str, value2: int | long, seed: int) -> int:
        return int(Murmur128Hash._inner_hash(value1.encode('utf-8'), 0, len(value1), seed))

    @staticmethod
    def _concat_byte_array(key: bytes, offset: int, length: int) -> bytearray:
        result = bytearray(length)
        for i in range(length):
            result[i] = key[offset + i]
        return result

    @staticmethod
    def get_block(key: bytes, offset: int, index: int) -> int | long:
        i8 = (index << 3)
        block_offset = offset + i8
        return ((key[block_offset]) & 0xff) \
               + (((key[block_offset + 1]) & 0xff) << 8) \
               + (((key[block_offset + 2]) & 0xff) << 16) \
               + (((key[block_offset + 3]) & 0xff) << 24) \
               + (((key[block_offset + 4]) & 0xff) << 32) \
               + (((key[block_offset + 5]) & 0xff) << 40) \
               + (((key[block_offset + 6]) & 0xff) << 48) \
               + (((key[block_offset + 7]) & 0xff) << 56)

    @staticmethod
    def rotl64(v: int | long, n: int) -> int | long:
        return ((v << n) | (v >> (64 - n)))

    @staticmethod
    def fmix(k: int | long) -> int | long:
        k ^= k >> 33
        k *= 0x87c37b91114253d5L
        k ^= k >> 33
        k *= 0xc4ceb9fe1a85ec53L
        k ^= k >> 33
        return k

    @staticmethod
    def _inner_hash(key: bytes, offset: int, length: int, seed: int) -> int | long:
        nblocks = length >> 4
        h1 = seed
        h2 = seed
        c1 = 0x87c37b91114253d5L
        c2 = 0x4cf5ad432745937fL

        for i in range(nblocks):
            k1 = Murmur128Hash.get_block(key, offset, i * 2)
            k2 = Murmur128Hash.get_block(key, offset, i * 2 + 1)
            k1 *= c1
            k1 = Murmur128Hash.rotl64(k1, 31)
            k1 *= c2
            h1 ^= k1
            h1 = Murmur128Hash.rotl64(h1, 27)
            h1 += h2
            h1 = (h1 * 5 + 0x52dce729) & ((1 << 32) - 1)

            k2 *= c2
            k2 = Murm