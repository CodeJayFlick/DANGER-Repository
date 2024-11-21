Here is the translation of the Java code into Python:

```Python
import unittest

class DisassembleContextTest(unittest.TestCase):

    def setUp(self):
        self.program = create_default_program("Test", "ARM")
        self.space = self.program.get_address_factory().get_default_address_space()
        tmode_reg = self.program.get_register("TMode")
        r0_reg = self.program.get_register("r0")

        self.program.start_transaction("TEST")
        self.program.memory.create_uninitialized_block("testBlock", self.space.get_address(0), 0x100, False)

    def tearDown(self):
        if self.program is not None:
            self.program.release(self)

    @unittest.skip
    def test_flow_with_save_into_program_context(self):

        retained_context = self.program.get_program_context()
        addr = self.space.get_address(0)
        
        context = DisassemblerContextImpl(retained_context)
        context.flow_start(addr)
        context.set_value(tmode_reg, ZERO)

        for i in range(20):
            addr = addr.next()
            context.flow_to_address(addr)

        self.assertEqual(ZERO, context.get_value(tmode_reg, addr.previous(), False))

        # should catch that addr is currentAddr
        self.assertEqual(ZERO, context.get_value(tmode_reg, addr, False))
        self.assertEqual(ZERO, context.get_value(tmode_reg, False))

        # explicit set of future value before flow-to
        addr = addr.add(30)
        context.set_value(tmode_reg, addr, ONE)

        # Flow-to set-point and check it out
        context.flow_to_address(addr)

        self.assertEqual(ZERO, retained_context.get_value(tmode_reg, addr.previous(), False))

        # original default value still present in program context
        self.assertIsNone(retained_context.get_value(tmode_reg, addr, False))

        # current disassembler context  - not yet stored to program context
        self.assertEqual(ONE, context.get_value(tmode_reg, False))
        self.assertEqual(ONE, context.get_value(tmode_reg, addr, False))

        # default context returned from address we have not yet flowed-to
        addr = addr.next()
        self.assertIsNone(context.get_value(tmode_reg, addr, False))

        # Indicate future flow  - context should be copied
        future_flow_addr = addr.add(50)
        context.copy_to_future_flow_state(future_flow_addr)

        # End flow causes current context to be written
        context.flow_end(addr)

        self.assertEqual(ONE, context.get_value(tmode_reg, addr, False))
        self.assertEqual(ONE, retained_context.get_value(tmode_reg, addr, False))

    @unittest.skip
    def test_flow_with_no_save_into_program_context(self):

        retained_context = ProgramContextImpl(self.program.language)
        addr = self.space.get_address(0)

        context = DisassemblerContextImpl(retained_context)
        context.flow_start(addr)
        context.set_value(tmode_reg, ZERO)

        for i in range(20):
            addr = addr.next()
            context.flow_to_address(addr)

        self.assertEqual(ZERO, context.get_value(tmode_reg, addr.previous(), False))

        # should catch that addr is currentAddr
        self.assertEqual(ZERO, context.get_value(tmode_reg, addr, False))
        self.assertEqual(ZERO, context.get_value(tmode_reg, False))

        # explicit set of future value before flow-to
        addr = addr.add(30)
        context.set_value(tmode_reg, addr, ONE)

        # Flow-to set-point and check it out
        context.flow_to_address(addr)

        self.assertIsNone(retained_context.get_value(tmode_reg, addr.previous(), False))

        # original default value still present in program context
        self.assertIsNone(retained_context.get_value(tmode_reg, addr, False))

        # current disassembler context  - not yet stored to program context
        self.assertEqual(ONE, context.get_value(tmode_reg, False))
        self.assertEqual(ONE, context.get_value(tmode_reg, addr, False))

        # default context returned from address we have not yet flowed-to
        addr = addr.next()
        self.assertIsNone(context.get_value(tmode_reg, addr, False))

        # Indicate future flow  - context should be copied
        future_flow_addr = addr.add(50)
        context.copy_to_future_flow_state(future_flow_addr)

        # End flow causes current context to be written
        context.flow_end(addr)

        self.assertIsNone(retained_context.get_value(tmode_reg, addr, False))

    @unittest.skip
    def test_flow_with_save_into_context_impl(self):

        retained_context = ProgramContextImpl(self.program.language)
        addr = self.space.get_address(0)

        context = DisassemblerContextImpl(retained_context)
        context.flow_start(addr)
        context.set_value(tmode_reg, ZERO)

        for i in range(20):
            addr = addr.next()
            context.flow_to_address(addr)

        self.assertEqual(ZERO, context.get_value(tmode_reg, addr.previous(), False))

        # should catch that addr is currentAddr
        self.assertEqual(ZERO, context.get_value(tmode_reg, addr, False))
        self.assertEqual(ZERO, context.get_value(tmode_reg, False))

        # explicit set of future value before flow-to
        addr = addr.add(30)
        context.set_value(tmode_reg, addr, ONE)

        # Flow-to set-point and check it out
        context.flow_to_address(addr)

        self.assertEqual(ZERO, retained_context.get_value(tmode_reg, addr.previous(), False))

        # original default value still present in program context
        self.assertIsNone(retained_context.get_value(tmode_reg, addr, False))

        # current disassembler context  - not yet stored to program context
        self.assertEqual(ONE, context.get_value(tmode_reg, False))
        self.assertEqual(ONE, context.get_value(tmode_reg, addr, False))

        # default context returned from address we have not yet flowed-to
        addr = addr.next()
        self.assertIsNone(context.get_value(tmode_reg, addr, False))

        # Indicate future flow  - context should be copied
        future_flow_addr = addr.add(50)
        context.copy_to_future_flow_state(future_flow_addr)

        # End flow causes current context to be written
        context.flow_end(addr)

        self.assertEqual(ONE, context.get_value(tmode_reg, addr, False))
        self.assertEqual(ONE, retained_context.get_value(tmode_reg, addr, False))

    @unittest.skip
    def test_flow_with_no_save_into_context_impl(self):

        retained_context = ProgramContextImpl(self.program.language)
        addr = self.space.get_address(0)

        context = DisassemblerContextImpl(retained_context)
        context.flow_start(addr)
        context.set_value(tmode_reg, ZERO)

        for i in range(20):
            addr = addr.next()
            context.flow_to_address(addr)

        self.assertEqual(ZERO, context.get_value(tmode_reg, addr.previous(), False))

        # should catch that addr is currentAddr
        self.assertEqual(ZERO, context.get_value(tmode_reg, addr, False))
        self.assertEqual(ZERO, context.get_value(tmode_reg, False))

        # explicit set of future value before flow-to
        addr = addr.add(30)
        context.set_value(tmode_reg, addr, ONE)

        # Flow-to set-point and check it out
        context.flow_to_address(addr)

        self.assertIsNone(retained_context.get_value(tmode_reg, addr.previous(), False))

        # original default value still present in program context
        self.assertIsNone(retained_context.get_value(tmode_reg, addr, False))

        # current disassembler context  - not yet stored to program context
        self.assertEqual(ONE, context.get_value(tmode_reg, False))
        self.assertEqual(ONE, context.get_value(tmode_reg, addr, False))

        # default context returned from address we have not yet flowed-to
        addr = addr.next()
        self.assertIsNone(context.get_value(tmode_reg, addr, False))

        # Indicate future flow  - context should be copied
        future_flow_addr = addr.add(50)
        context.copy_to_future_flow_state(future_flow_addr)

        # End flow causes current context to be written
        context.flow_end(addr)

        self.assertIsNone(retained_context.get_value(tmode_reg, addr, False)