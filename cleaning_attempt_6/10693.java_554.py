import unittest

class IteratorTest(unittest.TestCase):

    def test_all(self):
        pm = StringPropertySet("Test")
        for i in range(20):
            s = f"test {i+10}"
            pm.put_string(i + 10, s)
        
        it = pm.get_property_iterator(10, 30)

        i = 10
        while it.has_next():
            index = it.next()
            self.assertEqual(i, int(index))
            if it.has_previous():
                prev_index = it.previous()
                self.assertEqual(i, int(prev_index))
                it.next() # so we don't go into an infinite loop
            i += 1

        it = pm.get_property_iterator(12)
        i = 11
        while it.has_previous():
            index = it.previous()
            self.assertEqual(i, int(index)) 
            if it.has_next():
                next_index = it.next()
                self.assertEqual(i, int(next_index))
                it.previous() # so we don't go into an infinite loop
            i -= 1

        it = pm.get_property_iterator(5, 15)
        i = 10
        while it.has_next():
            index = it.next()
            self.assertEqual(i, int(index)) 
            if it.has_previous():
                prev_index = it.previous()
                self.assertEqual(i, int(prev_index))
                it.next() # so we don't go into an infinite loop
            i += 1

        pm.remove_range(0, 2000)
        it = pm.get_property_iterator(5, 15)
        if it.has_previous():
            self.fail()

if __name__ == '__main__':
    unittest.main()
