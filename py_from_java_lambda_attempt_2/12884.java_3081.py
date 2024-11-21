Here is the translation of the given Java code into Python:

```Python
import unittest

class MaskedLongTest(unittest.TestCase):

    def testShiftLeft(self):
        self.assertEqual(MaskedLong.from_long(0xfffffffffffffff8), MaskedLong.ones().shift_left(3))
        self.assertEqual(MaskedLong.zero(), MaskedLong.zero().shift_left(3))
        self.assertEqual(MaskedLong.from_mask_and_value(0x7, 0), MaskedLong.unknwns().shift_left(3))

    def testShiftRightLogical(self):
        self.assertEqual(MaskedLong.from_long(0x1fffffffffffffff), MaskedLong.ones().shift_right_logical(3))
        self.assertEqual(MaskedLong.zero(), MaskedLong.zero().shift_right_logical(3))
        self.assertEqual(MaskedLong.from_mask_and_value(0xe00000000000000, 0), MaskedLong.unknwns().shift_right_logical(3))

    def testShiftRight(self):
        self.assertEqual(MaskedLong.ones(), MaskedLong.ones().shift_right(3))
        self.assertEqual(MaskedLong.zero(), MaskedLong.zero().shift_right(3))
        self.assertEqual(MaskedLong.unknwns(), MaskedLong.unknwns().shift_right(3))

    def testInvShiftLeft(self):
        try:
            MaskedLong.from_long(0xfffffffffffffff8).inv_shift_left(3)
            self.fail()
        except Exception as e:
            pass

        self.assertEqual(MaskedLong.from_mask_and_value(0x1fffffffffffffff, 0x1fffffffffffffff), 
                         MaskedLong.from_long(0xfffffffffffffff8).inv_shift_left(3))
        self.assertEqual(MaskedLong.from_mask_and_value(0x1fffffffffffffff, 0), 
                         MaskedLong.zero().inv_shift_left(3))
        self.assertEqual(MaskedLong.unknwns(), MaskedLong.unknwns().inv_shift_left(3))

    def testInvShiftRight(self):
        try:
            MaskedLong.ones().inv_shift_right(3)
            self.fail()
        except Exception as e:
            pass

        self.assertEqual(MaskedLong.from_mask_and_value(0xfffffffffffffff8, 0xfffffffffffffff8), 
                         MaskedLong.ones().inv_shift_right(3))
        self.assertEqual(MaskedLong.from_mask_and_value(0xfffffffffffffff8, 0), 
                         MaskedLong.zero().inv_shift_right(3))
        self.assertEqual(MaskedLong.unknwns(), MaskedLong.unknwns().inv_shift_right(3))

    def testInvShiftRightLogical(self):
        try:
            MaskedLong.ones().inv_shift_right_logical(3)
            self.fail()
        except Exception as e:
            pass

        self.assertEqual(MaskedLong.from_mask_and_value(0xfffffffffffffff8, 0xfffffffffffffff8), 
                         MaskedLong.from_mask_and_value(0x1fffffffffffffff, 0x1fffffffffffffff).inv_shift_right_logical(3))
        self.assertEqual(MaskedLong.from_mask_and_value(0xfffffffffffffff8, 0), 
                         MaskedLong.from_mask_and_value(0x1fffffffffffffff, 0).inv_shift_right_logical(3))
        self.assertEqual(MaskedLong.unknwns(), MaskedLong.unknwns().inv_shift_right_logical(3))

if __name__ == '__main__':
    unittest.main()
```

Note: The Python code is not exactly the same as the Java code, but it should give you a good idea of how to translate your Java test cases into Python.