class Heap:
    N = None
    heapSize = 0
    arr = []

    def init(self, n):
        self.N = n
        self.arr = [None] * (n + 1)
        self.heapSize = 0

    def add(self, n):
        self.arr[self.heapSize+1] = n
        i = self.heapSize
        while True:
            if i > 0 and self.arr[i] < self.arr[i//2]:
                self.swap(i//2, i)
                i //= 2
            else:
                break

    def remove(self):
        if self.heapSize == 0: return None
        
        rm = self.arr[1]
        self.arr[1] = self.arr[self.heapSize]
        self.arr[self.heapSize-1] = None
        self.heapSize -= 1

        i = 1
        while True:
            if i*2+1 <= self.heapSize and (self.arr[i] < self.arr[i*2] or self.arr[i] < self.arr[i*2+1]):
                if self.arr[i*2] > self.arr[i*2+1]:
                    self.swap(i, i*2)
                    i = 2*i
                else:
                    self.swap(i, i*2+1)
                    i = 2*i + 1
            elif i*2 <= self.heapSize and self.arr[i] < self.arr[2*i]:
                self.swap(i, 2*i)
                i = 2*i
            else: break

        return rm

    def swap(self, a, b):
        temp = self.arr[a]
        self.arr[a] = self.arr[b]
        self.arr[b] = temp
