import time

class TestSpeed:
    def __init__(self):
        pass

    @staticmethod
    def create_buf():
        buf = bytearray(16 * 1024)

        for i in range(2 * 1024):
            put_long(buf, i, i)
        return buf

    @staticmethod
    def put_long(data, index, v):
        i = index * 8
        data[i] = (v >> 56) & 0xff
        data[i + 1] = (v >> 48) & 0xff
        data[i + 2] = (v >> 40) & 0xff
        data[i + 3] = (v >> 32) & 0xff
        data[i + 4] = (v >> 24) & 0xff
        data[i + 5] = (v >> 16) & 0xff
        data[i + 6] = (v >> 8) & 0xff
        data[i + 7] = v & 0xff

    @staticmethod
    def test1(buf):
        search1 = JavaBinarySearcher()
        nKeys = 2048

        start = time.time()
        for j in range(1000):
            for i in range(nKeys):
                index = search1.binary_search(buf, i, nKeys)
                if index != i:
                    print("search failed")
        end = time.time()
        print(f"Done, time = {end - start}")

    @staticmethod
    def test2(buf):
        search1 = JavaBinarySearcher2()
        nKeys = 2048

        start = time.time()
        for j in range(1000):
            for i in range(nKeys):
                index = search1.binary_search(buf, i, nKeys)
                if index != i:
                    print("search failed")
        end = time.time()
        print(f"Done, time = {end - start}")


class JavaBinarySearcher:
    def binary_search(self, buf, key, nKeys):
        min = 0
        max = nKeys - 1

        while min <= max:
            i = (min + max) // 2
            k = self.get_key(buf, i)
            if k == key:
                return i
            elif k < key:
                min = i + 1
            else:
                max = i - 1
        return -(min + 1)

    def get_key(self, buf, i):
        data = bytearray(8)
        for j in range(8):
            data[j] = buf[i * 8 + j]
        return ((data[0] & 0xff) << 56) | \
               ((data[1] & 0xff) << 48) | \
               ((data[2] & 0xff) << 40) | \
               ((data[3] & 0xff) << 32) | \
               ((data[4] & 0xff) << 24) | \
               ((data[5] & 0xff) << 16) | \
               ((data[6] & 0xff) << 8) | (data[7] & 0xff)


class JavaBinarySearcher2(JavaBinarySearcher):
    pass


TestSpeed().test1(TestSpeed.create_buf())
TestSpeed().test2(TestSpeed.create_buf())
