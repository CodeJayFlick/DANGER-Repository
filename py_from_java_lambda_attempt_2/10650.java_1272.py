Here is the translation of the given Java code into Python:

```Python
class AlgorithmsTest:
    def __init__(self):
        self.comparator = lambda a, b: -1 if a < b else 0 if a == b else 1

    def get_list(self, data):
        return [x for x in data]

    def test_bubble_sort(self):
        data = [5, 8, 10, 2, 10, 3, 3, 7, 10, 23, 0, 15, 22]
        Algorithms.bubbleSort(data[:], 3, 8, self.comparator)
        expected = [5, 8, 10, 2, 3, 3, 7, 10, 10, 23, 0, 15, 22]
        for i in range(len(expected)):
            assert data[i] == expected[i]

    def test_merge_sort(self):
        data = [5, 8, 10, 2, 10, 3, 3, 7, 10, 23, 0, 15, 22]
        Algorithms.mergeSort(data[:], self.comparator)
        expected = [0, 2, 3, 3, 5, 7, 8, 10, 10, 10, 15, 22, 23]
        for i in range(len(expected)):
            assert data[i] == expected[i]

    def test_merge_sort_2(self):
        data = [0, 1, 2, 3, 4, 0, 0, 0]
        Algorithms.mergeSort(data[:], self.comparator)
        expected = [0, 0, 0, 0, 1, 2, 3, 4]
        for i in range(len(expected)):
            assert data[i] == expected[i]

    def test_merge_sort_3(self):
        data = [0, 1, 2, 3, 4, 4, 4, 4]
        Algorithms.mergeSort(data[:], self.comparator)
        expected = [0, 1, 2, 3, 4, 4, 4, 4]
        for i in range(len(expected)):
            assert data[i] == expected[i]

    def test_merge_sort_4(self):
        data = [1, 1, 1, 1, 1, 1, 1, 1]
        Algorithms.mergeSort(data[:], self.comparator)
        expected = [1, 1, 1, 1, 1, 1, 1, 1]
        for i in range(len(expected)):
            assert data[i] == expected[i]

    def test_merge_sort_5(self):
        l = [random.randint(0, 100000) for _ in range(100000)]
        Algorithms.mergeSort(l[:], self.comparator)
        for i in range(len(l)-1):
            assert l[i] <= l[i+1]

    def test_binary_search(self):
        data = [0, 2, 3, 3, 5, 7, 8, 10, 10, 15, 22, 23]
        assert sorted(data).index(0) == 0
        assert sorted(data).index(5) == 4
        assert sorted(data).index(23) == 11
        assert -1 in [sorted(data).index(x) for x in [-12, 9]]
        assert -14 in [sorted(data).index(x) for x in [50]]

if __name__ == "__main__":
    test = AlgorithmsTest()
    test.test_bubble_sort()
    test.test_merge_sort()
    test.test_merge_sort_2()
    test.test_merge_sort_3()
    test.test_merge_sort_4()
    test.test_merge_sort_5()
    test.test_binary_search()

```

Note: The `Algorithms` class and its methods (`bubbleSort`, `mergeSort`) are not defined in the given Java code. Therefore, I have assumed that these classes and their methods exist elsewhere in your Python program or library.