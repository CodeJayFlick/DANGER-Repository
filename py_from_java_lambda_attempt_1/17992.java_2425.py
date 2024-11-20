Here is the equivalent Python code:

```Python
class CopyOnReadLinkedList:
    def __init__(self):
        self.list = []

    def add(self, item):
        self.list.append(item)

    def reset(self):
        self.list.clear()

    def contains(self, item):
        return item in self.list

    def remove(self, item):
        if item in self.list:
            self.list.remove(item)

    def clone_list(self):
        import copy
        return copy.deepcopy(self.list)


import unittest

class TestCopyOnReadLinkedList(unittest.TestCase):

    def test_modify_list(self):
        slist = CopyOnReadLinkedList()
        str1 = "aaa"
        str2 = "bbb"
        slist.add(str1)
        slist.add(str2)

        iterator = iter(slist.list)
        self.assertEqual(next(iterator), str1)
        self.assertEqual(next(iterator), str2)

        slist.reset()
        if str1 in slist.list:
            slist.remove(str1)
        self.assertEqual(1, len(slist.list))

        str2 = "ddd"
        iterator = iter(slist.list)
        self.assertNotEqual(next(iterator), str2)


    def test_clone_modified_list(self):
        slist = CopyOnReadLinkedList()
        str1 = "aaa"
        str2 = "bbb"
        slist.add(str1)
        slist.add(str2)

        str2 = "ddd"  # str2 in slist is not modified
        clist = slist.clone_list().copy()  # clone the list and copy it to avoid modifying original list

        self.assertEqual("aaa", clist[0])
        self.assertEqual("bbb", clist[1])
        self.assertFalse(clist == [])

if __name__ == '__main__':
    unittest.main()
```

This Python code is equivalent to the Java code provided. It defines a `CopyOnReadLinkedList` class with methods similar to those in the original Java code, and then tests these methods using the `unittest` module.