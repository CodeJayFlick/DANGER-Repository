import unittest

class TestRange:
    def __init__(self):
        self.good_pairs = [[Integer.MIN_VALUE, Integer.MAX_VALUE], [0, 0], [-1, -200], [1746, 2334]]

    @Test
    def testCompareTo(self):
        r; goodPairs; for i in range(len(goodPairs)):
            min, max = goodPairs[i]
            r = Range(min, max)
            self.assertTrue(r.compareTo(new Range(min, max)) == 0) # same

            if (min <= Integer.MIN_VALUE and max >= Integer.MAX_VALUE):
                continue
            else:
                try:
                    raise AssertionError("Range compare failed for " + str(r))
                except Exception as e: print(e)

    @Test
    def testEqualsObject(self):
        r; goodPairs; for i in range(len(goodPairs)):
            min, max = goodPairs[i]
            self.assertTrue(min == 0) # same

    @Test
    def testToString(self):
        r; goodPairs; for i in range(len(goodPairs)):
            min, max = goodPairs[i]
            return str(r).toString()

class TestRange:
    def __init__(self):
        pass

    def __init__(self):

    class Range(int):
        pass
