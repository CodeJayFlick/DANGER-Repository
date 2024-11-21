import unittest


class MinLengthCharSequenceMatcherTest(unittest.TestCase):

    def testBasic(self):
        matcher = MinLengthCharSequenceMatcher(3, AsciiCharSetRecognizer(), 1)
        
        values = [0, 1, 2, ord('a'), ord('b'), ord('c'), ord('d'), 3, 4, 5]
        matches = []
        for value in values:
            if matcher.add_char(value):
                matches.append(matcher.get_sequence())
                
        self.assertEqual(1, len(matches))
        self.assertEqual((0, 6), matches[0])

    def testMultiple(self):
        matcher = MinLengthCharSequenceMatcher(3, AsciiCharSetRecognizer(), 1)
        
        values = [0, 1, 2, ord('a'), ord('b'), ord('c'), ord('d'), 3, 4, 5, ord('e'), ord('f'), ord('g'), 0, 1]
        matches = []
        for value in values:
            if matcher.add_char(value):
                matches.append(matcher.get_sequence())
                
        self.assertEqual(2, len(matches))
        self.assertEqual((3, 6), matches[0])
        self.assertEqual((10, 13), matches[1])

    def testStringAtStart(self):
        matcher = MinLengthCharSequenceMatcher(3, AsciiCharSetRecognizer(), 1)
        
        values = [ord('a'), ord('b'), ord('c'), ord('d'), 0, 1]
        matches = []
        for value in values:
            if matcher.add_char(value):
                matches.append(matcher.get_sequence())
                
        self.assertEqual(1, len(matches))
        self.assertEqual((0, 4), matches[0])

    def testStringAtEndNoZeroTermination(self):
        matcher = MinLengthCharSequenceMatcher(3, AsciiCharSetRecognizer(), 1)
        
        values = [0, ord('a'), ord('b'), ord('c'), ord('d')]
        matches = []
        for value in values:
            if matcher.add_char(value):
                matches.append(matcher.get_sequence())
                
        self.assertEqual(0, len(matches))
        self.assertTrue(matcher.end_sequence())
        self.assertEqual((1, 4), matcher.get_sequence())

    def testAlignment(self):
        matcher = MinLengthCharSequenceMatcher(3, AsciiCharSetRecognizer(), 2)
        
        values = [0, ord('a'), ord('b'), ord('c'), ord('d'), 0, 0]
        matches = []
        for value in values:
            if matcher.add_char(value):
                matches.append(matcher.get_sequence())
                
        self.assertEqual(1, len(matches))
        self.assertEqual((2, 5), matches[0])


if __name__ == '__main__':
    unittest.main()
