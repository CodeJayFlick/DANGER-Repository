class ObjectIntHashtableTest:
    def __init__(self):
        pass

    @staticmethod
    def test(ht, key, value):
        try:
            if ht.get(key) != value:
                assert False, f"Value at key {key} should be {value}, but instead is {ht.get(key)}"
        except KeyError:
            assert False, f"No value found at key {key} but should have had value {value}"

    @staticmethod
    def test_contains(ht, keys):
        for i in range(len(keys)):
            if not ht.contains(str(keys[i])):
                assert False, f"hastable should contain key {keys[i]}, but it doesn't"
        
        for i in range(50001):  # Python indexing starts from 0, so we need to go up to 50000
            if str(i) in keys:
                return

    def test_object_int_hashtable(self):
        ht = ObjectIntHashtable()
        print("Test put method")

        ht.put("A", 100)
        ht.put("B", 200)
        ht.put("C", 300)
        ht.put("D", 400)

        self.test(ht, "A", 100)
        self.test(ht, "B", 200)
        self.test(ht, "C", 300)
        self.test(ht, "D", 400)

        try:
            _ = ht.get("G")
            assert False, f"The value {_} was found at key G, but there should not have been a value there."
        except KeyError:
            pass

        print("Test contains method")

        test_contains(ht, ["A", "B", "C", "D"], "Add")

        print("Test size method")
        if ht.size() != 4:
            assert False, f"size should be 4, but it is {ht.size()}"

        print("Test remove")
        self.assertTrue(ht.remove("B"))
        self.assertFalse(ht.remove("Z"))

        if ht.size() != 3:
            assert False, f"size should be 3, but it is {ht.size()}"

        test_contains(ht, ["A", "C", "D"], "Remove")

        print("Test removeAll")
        ht.removeAll()
        if ht.size() != 0:
            assert False, f"size should be 0, but it is {ht.size()}"

        test_contains(ht, [], "RemoveAll")

        print("Test grow by adding 500 values")
        for i in range(500):
            ht.put(f"L{100*i}", i)

        for i in range(50000):  # Python indexing starts from 0, so we need to go up to 50000
            if str(i) in ht:
                if i % 100 != 0:
                    assert False, f"hashtable contains key {i}, but it shouldn't"
            else:
                if i % 100 == 0:
                    assert False, f"hashtable should contain key {i}, but it doesn't"


class ObjectIntHashtable:
    def __init__(self):
        pass

    def put(self, key, value):
        # implement your logic here
        pass

    def get(self, key):
        # implement your logic here
        raise KeyError("No value found at this key")

    def contains(self, key):
        return False  # implement your logic here

    def size(self):
        return 0  # implement your logic here

    def remove(self, key):
        pass  # implement your logic here

    def removeAll(self):
        pass  # implement your logic here
