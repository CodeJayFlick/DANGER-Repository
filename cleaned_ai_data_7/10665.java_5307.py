class LongIntHashtableTest:
    def __init__(self):
        pass

    @staticmethod
    def test_long_int_hashtable():
        ht = {}
        print("Test put method")

        for i in range(40000, 50001, 10000):
            ht[i] = i // 10

        for key in ht:
            assert ht[key] == key // 10

        try:
            value = ht[50000]
            assert False, f"The value {value} was found at key 50000, but there should not have been a value there."
        except KeyError:
            pass

        print("Test contains method")

        keys_to_test = list(ht.keys())
        for i in range(len(keys_to_test)):
            if not ht.__contains__(keys_to_test[i]):
                assert False, f"hashtable should contain key {keys_to_test[i]}, but it doesn't"

        for i in range(50000):
            if i % 100 == 0 and i not in keys_to_test:
                assert False, f"hashtable contains key {i}, but it shouldn't"
            elif i % 100 != 0 and i in keys_to_test:
                assert False, f"hashtable should contain key {i}, but it doesn't"

        print("Test size method")
        if len(ht) != 4:
            assert False, f"size should be 4, but it is {len(ht)}"

        print("Test remove")
        ht.pop(20000)
        if len(ht) != 3:
            assert False, f"size should be 3, but it is {len(ht)}"
        for key in ht:
            if key == 30000 or key == 40000:
                return
        assert False, "remove didn't work"

        print("Test removeAll")
        ht.clear()
        if len(ht) != 0:
            assert False, f"size should be 0, but it is {len(ht)}"
