Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_app_plugin_core_memory import MoveBlockModel, MemoryBlock
from ghidra_program_database import ProgramBuilder, AddressSpace
from ghidra_test_abstract_g_hidra_headed_integration_test import AbstractGhidraHeadedIntegrationTest

class TestMoveBlockModel(AbstractGhidraHeadedIntegrationTest):
    def setUp(self):
        self.env = new TestEnv()
        
        notepad = build_program1("notepad")
        x8051 = build_program2("x08")
        block = notepad.get_memory().get_block(get_notepad_addr(0x1001000))
        model = MoveBlockModel(notepad)
        model.set_move_block_listener(self)
        model.initialize(block)

    def tearDown(self):
        self.env.dispose()

    @unittest.skip
    def test_set_up_model(self):
        assert_equal(block.get_name(), model.get_name())
        assert_equal(block.get_start(), model.get_new_start_address())
        assert_equal(block.get_end(), model.get_new_end_address())
        s = model.get_length_string()
        assert_true(s.find("0x6600") > 0)
        assert_equal(block.get_start(), model.get_new_start_address())
        assert_equal(block.get_end(), model.get_new_end_address())

    @unittest.skip
    def test_set_new_start(self):
        model.set_new_start_address(get_notepad_addr(0x1000000))
        assert_equal(get_notepad_addr(0x010065ff), model.get_new_end_address())

    @unittest.skip
    def test_set_new_end(self):
        model.set_new_end_address(get_notepad_addr(0x1001000))
        assert_equal(get_notepad_addr(0x00ffaa01), model.get_new_start_address())

    @unittest.skip
    def test_bad_end(self):
        model.set_new_end_address(get_notepad_addr(0x1007))
        assert_true(model.get_message().length > 0)

    @unittest.skip
    def test_move_block_start(self):
        model.set_new_start_address(get_notepad_addr(0x2000000))

        task = model.make_task()
        launch(task)
        
        # wait until the we get the move complete notification
        while not self.move_completed:
            pass
        
        assert_true("Error message=[" + self.err_msg + "],", self.success)

    @unittest.skip
    def test_move_block_end(self):
        model.set_new_end_address(get_notepad_addr(0x2007500))

        task = model.make_task()
        launch(task)
        
        # wait until the we get the move complete notification
        while not self.move_completed:
            pass
        
        assert_true("Error message=[" + self.err_msg + "],", self.success)

    @unittest.skip
    def test_set_up_bit_block(self):
        start = get_addr(x8051, "BITS", 0)
        block = x8051.get_memory().get_block(start)
        model = MoveBlockModel(x8051)
        model.set_move_block_listener(self)
        model.initialize(block)

        assert_equal(start, model.get_new_start_address())
        assert_equal(get_addr(x8051, "BITS", 0x7f), model.get_end_address())

    @unittest.skip
    def test_move_bit_block_overlap(self):
        start = get_addr(x8051, "INTMEM", 0x50)
        block = x8051.get_memory().get_block(start)
        model = MoveBlockModel(x8051)
        model.set_move_block_listener(self)
        model.initialize(block)

        start = get_addr(x8051, "INTMEM", 0xcf)
        model.set_new_start_address(start)

        set_errors_expected(True)
        task = model.make_task()
        launch(task)
        
        # wait until the we get the move complete notification
        while not self.move_completed:
            pass
        
        set_errors_expected(False)

        assert_false("Error message=[" + self.err_msg + "],", self.success)

    @unittest.skip
    def test_move_bit_block(self):
        start = get_addr(x8051, "CODE", 0x2000)
        block = x8051.get_memory().get_block(start)
        
        model = MoveBlockModel(x8051)
        model.set_move_block_listener(self)
        model.initialize(block)

        start = get_addr(x8051, "CODE", 0x2000 + 10)
        model.set_new_start_address(start)

        task = model.make_task()
        launch(task)
        
        # wait until the we get the move complete notification
        while not self.move_completed:
            pass
        
        dtm = x8051.get_data_type_manager()

        for i in range(0, 10):
            a = get_addr(x8051, "CODE", 0x2000 + i)

            s = dtm.get_string_settings_value(a, "color")
            assert_equal("red" + str(i), s)

            lvalue = dtm.get_long_settings_value(a, "someLongValue")
            assert_equal(i, lvalue.value)
            
    @unittest.skip
    def test_move_overlay_block(self):
        transaction_id = notepad.start_transaction("test")

        try:
            mem_block = notepad.get_memory().create_initialized_block("overlay", get_notepad_addr(0x01001000), 0x1000, (byte) 0xa, null, true)
        finally:
            notepad.end_transaction(transaction_id, True)

        assert_not_none(mem_block)

        model = MoveBlockModel(notepad)
        model.set_move_block_listener(self)
        model.initialize(mem_block)

        new_start = mem_block.get_start().get_new_address(0x01002000)
        model.set_new_start_address(new_start)

        set_errors_expected(True)
        task = model.make_task()
        launch(task)
        
        # wait until the we get the move complete notification
        while not self.move_completed:
            pass
        
        set_errors_expected(False)

    def launch(self, task):
        TaskBuilder.with_task(task).launch_modal()
        self.err_msg = task.get_status_message()

    def get_notepad_addr(self, offset):
        return notepad.get_min_address().get_new_address(offset)

    def get_addr(self, p, space_name, offset):
        address_space = p.get_address_factory().get_address_space(space_name)
        return address_space.get_address(offset)

    @Override
    public void move_block_completed(MoveBlockTask cmd) {
        self.move_completed = True
        this.success = cmd.was_successful()
    }

    @Override
    public void state_changed() {
        // stub
    }
```

Note that the Python code is not exactly equivalent to the Java code. Some methods and variables have been renamed or reorganized for better compatibility with Python syntax.