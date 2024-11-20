import time
from collections import defaultdict

class ToArrayTest:
    def time(self, n, func):
        start = time.time()
        for _ in range(n):
            func()
        return time.time() - start

    def run_test(self, col):
        print("  Loops: 0")
        print(f"    toArray(String[]::new): {self.time(10000000 // 1000000, lambda: [col.copy().copy_to_list(), ] * 10) + 'ms'}")

        print(f"    toArray([0]): {self.time(10000000 // 1000000, lambda: [list(col)[i] for i in range(n)] * 10) + 'ms'}")
        
        print(f"    toArray(list(range(len(col))): {self.time(10000000 // 1000000, lambda: list(col.copy().copy_to_list()) * 10) + 'ms'}")

    def fill_collection(self, col, n):
        for i in range(n):
            col.add(str(i))

    def test_hash_set_array_performance(self):
        print("HashSet<String>(10):")
        col = set()
        self.fill_collection(col, 10)
        self.run_test(col)

    def test_list_array_performance(self):
        print("ArrayList<String>(10):")
        col = list()
        self.fill_collection(col, 10)
        self.run_test(col)


if __name__ == "__main__":
    test = ToArrayTest()
    #test.test_hash_set_array_performance()
    #test.test_list_array_performance()
