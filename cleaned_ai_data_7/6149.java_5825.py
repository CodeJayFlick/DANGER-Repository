import time
import sys

class TestBuffer:
    SIZE = 1000000
    LOOPS = 100
    
    def __init__(self, size):
        self.data = bytearray(size * 4)
    
    def put(self, index, value):
        a = (value >> 24).to_bytes(1, 'big')
        b = ((value >> 16) & 0x00ff0000).to_bytes(1, 'big')
        c = ((value >> 8) & 0x0000ff00).to_bytes(1, 'big')
        d = (value & 0x000000ff).to_bytes(1, 'big')
        
        i = index * 4
        self.data[i:i+4] = a + b + c + d
    
    def get(self, index):
        i = index * 4
        a = int.from_bytes(self.data[i:i+1], 'big') << 24
        b = int.from_bytes(self.data[i+1:i+3], 'big') << 16 & 0x00ff0000
        c = int.from_bytes(self.data[i+2:i+4], 'big') << 8 & 0x0000ff00
        d = int.from_bytes(self.data[i+3:], 'big') & 0x000000ff
        
        return a | b | c | d


def main():
    start_time = time.time()
    print("start")
    
    buffer = TestBuffer(TestBuffer.SIZE)
    
    for _ in range(TestBuffer.LOOPS):
        for i in range(TestBuffer.SIZE):
            buffer.put(i, i)
        
        for i in range(TestBuffer.SIZE):
            if buffer.get(i) != i:
                print(f"expected {i} but got {buffer.get(i)}")
    
    print("done")
    print(f"time = {(time.time() - start_time):.2f}")
    
    end_time = time.time()
    start_time = end_time
    
    for _ in range(TestBuffer.LOOPS):
        d = [i for i in range(TestBuffer.SIZE)]
        
        for i in range(TestBuffer.SIZE):
            if d[i] != i:
                print(f"expected {i} but got {d[i]}")
    
    print("done 2")
    print(f"time = {(time.time() - start_time):.2f}")
    
    bb = bytearray(TestBuffer.SIZE * 4)
    
    for _ in range(TestBuffer.LOOPS):
        for i in range(TestBuffer.SIZE):
            bb[i*4:i*4+4] = int.to_bytes(i, 4, 'big')
        
        for i in range(TestBuffer.SIZE):
            if int.from_bytes(bb[i*4:i*4+4], 'big') != i:
                print(f"expected {i} but got {int.from_bytes(bb[i*4:], 'big')}")
    
    print("done 3")
    print(f"time = {(time.time() - start_time):.2f}")


if __name__ == "__main__":
    main()
