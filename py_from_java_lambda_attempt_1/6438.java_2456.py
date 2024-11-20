Here is the translation of the Java code into Python:

```Python
class FollowFlowForwardTest:
    def test_follow_all_flows_from_0x0(self):
        flow_addresses = self.get_flows_from(0x0, self.follow_all_flows())
        expected_addresses = AddressSet()
        for i in range(1, 16):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_all_flows_from_0x10(self):
        flow_addresses = self.get_flows_from(0x10, self.follow_all_flows())
        expected_addresses = AddressSet()
        for i in range(2, 17):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_all_flows_from_0x17(self):
        flow_addresses = self.get_flows_from(0x17, self.follow_all_flows())
        expected_addresses = AddressSet()
        for i in range(2, 5):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_all_flows_from_0x2f(self):
        flow_addresses = self.get_flows_from(0x2f, self.follow_all_flows())
        expected_addresses = AddressSet()
        for i in range(7, 8):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_all_flows_from_0x47(self):
        flow_addresses = self.get_flows_from(0x47, self.follow_all_flows())
        expected_addresses = AddressSet()
        for i in range(12, 13):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_all_flows_from_0x77(self):
        flow_addresses = self.get_flows_from(0x77, self.follow_all_flows())
        expected_addresses = AddressSet()
        for i in range(19, 20):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_all_flows_from_0x5000(self):
        flow_addresses = self.get_flows_from(0x5000, self.follow_all_flows())
        expected_addresses = AddressSet()
        for i in range(125, 126):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_all_flows_from_0x5020(self):
        flow_addresses = self.get_flows_from(0x5020, self.follow_all_flows())
        expected_addresses = AddressSet()
        for i in range(126, 127):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_unconditional_call_0x0(self):
        flow_addresses = self.get_flows_from(0x0, self.follow_only_unconditional_calls())
        expected_addresses = AddressSet()
        for i in range(2):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_unconditional_call_0xb(self):
        flow_addresses = self.get_flows_from(0xb, self.follow_only_unconditional_calls())
        expected_addresses = AddressSet()
        for i in range(3, 5):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_unconditional_call_0xf(self):
        flow_addresses = self.get_flows_from(0xf, self.follow_only_unconditional_calls())
        expected_addresses = AddressSet()
        for i in range(5, 7):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_conditional_call_0x0(self):
        flow_addresses = self.get_flows_from(0x0, self.follow_only_conditional_calls())
        expected_addresses = AddressSet()
        for i in range(2):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_conditional_call_0xe(self):
        flow_addresses = self.get_flows_from(0xe, self.follow_only_conditional_calls())
        expected_addresses = AddressSet()
        for i in range(5, 7):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_computed_call_0x0(self):
        flow_addresses = self.get_flows_from(0x0, self.follow_only_computed_calls())
        expected_addresses = AddressSet()
        for i in range(2):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_computed_call_0x25(self):
        flow_addresses = self.get_flows_from(0x25, self.follow_only_computed_calls())
        expected_addresses = AddressSet()
        for i in range(7, 9):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_unconditional_jump_0x0(self):
        flow_addresses = self.get_flows_from(0x0, self.follow_only_unconditional_jumps())
        expected_addresses = AddressSet()
        for i in range(2):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_unconditional_jump_0xb(self):
        flow_addresses = self.get_flows_from(0xb, self.follow_only_unconditional_jumps())
        expected_addresses = AddressSet()
        for i in range(3, 5):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_unconditional_jump_0x3b(self):
        flow_addresses = self.get_flows_from(0x3b, self.follow_only_unconditional_jumps())
        expected_addresses = AddressSet()
        for i in range(11, 13):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_conditional_jump_0x0(self):
        flow_addresses = self.get_flows_from(0x0, self.follow_only_conditional_jumps())
        expected_addresses = AddressSet()
        for i in range(2):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_conditional_jump_0xb(self):
        flow_addresses = self.get_flows_from(0xb, self.follow_only_conditional_jumps())
        expected_addresses = AddressSet()
        for i in range(3, 5):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_conditional_jump_0x21(self):
        flow_addresses = self.get_flows_from(0x21, self.follow_only_conditional_jumps())
        expected_addresses = AddressSet()
        for i in range(5, 7):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_computed_jump_0x0(self):
        flow_addresses = self.get_flows_from(0x0, self.follow_only_computed_jumps())
        expected_addresses = AddressSet()
        for i in range(2):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_computed_jump_0x21(self):
        flow_addresses = self.get_flows_from(0x21, self.follow_only_computed_jumps())
        expected_addresses = AddressSet()
        for i in range(5, 7):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_pointers_0x0(self):
        flow_addresses = self.get_flows_from(0x0, self.follow_only_pointers())
        expected_addresses = AddressSet()
        for i in range(2):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_pointers_0x5048(self):
        flow_addresses = self.get_flows_from(0x5048, self.follow_only_pointers())
        expected_addresses = AddressSet()
        for i in range(129, 132):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_pointers_0x290(self):
        flow_addresses = self.get_flows_from(0x290, self.follow_only_pointers())
        expected_addresses = AddressSet()
        for i in range(73, 74):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_pointers_0x390(self):
        flow_addresses = self.get_flows_from(0x390, self.follow_only_pointers())
        expected_addresses = AddressSet()
        for i in range(97, 98):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_pointers_0x5000(self):
        flow_addresses = self.get_flows_from(0x5000, self.follow_only_pointers())
        expected_addresses = AddressSet()
        for i in range(125, 126):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_pointers_0x5034(self):
        flow_addresses = self.get_flows_from(0x5034, self.follow_only_pointers())
        expected_addresses = AddressSet()
        for i in range(127, 128):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def test_follow_all_jumps_0x0(self):
        flow_addresses = self.get_flows_from(0x0, self.follow_all_jumps())
        expected_addresses = AddressSet()
        for i in range(2):
            expected_addresses.add(addr(i*4), addr((i+1)*4-1))
        self.assertEqual(MySelection(expected_addresses), MySelection(flow_addresses))

    def get_address_set(self, startAddress, endAddress):
        return new AddressSet(startAddress, endAddress)

    def follow_all_flows(self):
        # implementation
        pass

    def follow_only_unconditional_calls(self):
        # implementation
        pass

    def follow_only_conditional_calls(self):
        # implementation
        pass

    def follow_only_computed_jumps(self):
        # implementation
        pass

    def get_flows_from(self, startAddress, endAddress):
        return new AddressSet(startAddress, endAddress)

class MySelection:
    def __init__(self, addresses):
        self.addresses = addresses