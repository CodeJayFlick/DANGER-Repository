Here is the translation of the given Java code into Python:

```Python
import unittest

class AddressMapImplTest(unittest.TestCase):

    def setUp(self):
        self.sp8 = GenericAddressSpace("ONE", 8, "RAM", 0)
        self.sp16 = GenericAddressSpace("TWO", 16, "RAM", 1)
        self.sp32 = GenericAddressSpace("THREE", 32, "RAM", 2)
        self.sp64 = GenericAddressSpace("FOUR", 64, "RAM", 2)

        self.ov64 = OverlayAddressSpace("four", self.sp64, 100, 0x1000, 0x1fff)

        self.segSpace1 = SegmentedAddressSpace("SegSpaceOne", 3)
        self.segSpace2 = SegmentedAddressSpace("SegSpaceTwo", 4)

        self.regSpace = GenericAddressSpace("Register", 32, "REGISTER", 0)
        self.stackSpace = GenericAddressSpace("stack", 32, "STACK", 0)

        self.map = AddressMapImpl()
        self.addrs = [None] * 31
        for i in range(30):
            if i < 8:
                self.addrs[i] = self.sp8.getAddress(i)
            elif i < 16:
                self.addrs[i] = self.sp16.getAddress(i - 8)
            elif i < 32:
                self.addrs[i] = self.sp32.getAddress(i - 16)
            else:
                if i == 30:
                    self.addrs[i] = self.ov64.getAddress(0x1100)
                else:
                    self.addrs[i] = self.ov64.getAddress(0x2000)

    def testGetIndex(self):
        values = [None] * len(self.addrs)
        addrValues = [None] * len(self.addrs)

        for i in range(len(self.addrs)):
            values[i] = self.map.getKey(self.addrs[i])

        for i in range(len(addrValues)):
            addrValues[i] = self.map.decodeAddress(values[i])

        for i in range(len(self.addrs)):
            assertEqual(self.addrs[i], addrValues[i])

    def testGetEffectiveValue(self):
        assertEquals(self.map.getKey(self.addrs[0]), self.map.getKey(self.addrs[0]))
        assertTrue(self.map.getKey(self.addrs[12]) == self.map.getKey(self.addrs[12]))

        segA = SegmentedAddress(self.segSpace1, 0x1234, 5)
        effValue = self.map.getKey(segA)
        segB = SegmentedAddress(self.map.decodeAddress(effValue))
        assertEquals(0x1000, segB.getSegment())
        assertEquals(0x2345, segB.getSegmentOffset())

        addr = GenericAddress(self.sp8, 0)
        effValue = self.map.getKey(addr)
        a = self.map.decodeAddress(effValue)
        assertEqual(addr, a)

    def testRegisterAddress(self):
        a = self.regSpace.getAddress(0)
        key = self.map.getKey(a)
        b = self.map.decodeAddress(key)
        assertEquals(a, b)

        a = self.regSpace.getAddress(10)
        key = self.map.getKey(a)
        b = self.map.decodeAddress(key)
        assertEquals(a, b)

    def testStackAddress(self):
        a = self.stackSpace.getAddress(0)
        key = self.map.getKey(a)
        b = self.map.decodeAddress(key)
        assertEquals(a, b)

        a = self.stackSpace.getAddress(10)
        key = self.map.getKey(a)
        b = self.map.decodeAddress(key)
        assertEquals(a, b)


if __name__ == '__main__':
    unittest.main()
```

Note: The Python code is written in such a way that it can be run as a standalone script.