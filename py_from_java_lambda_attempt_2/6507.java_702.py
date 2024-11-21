Here is the translation of the Java code into Python:

```Python
import unittest

class PairedTransactionTest(unittest.TestCase):

    def setUp(self):
        self.obj1 = DummyDomainObject("obj1", self)
        self.obj2 = DummyDomainObject("obj2", self)

        tx_id = self.obj1.start_transaction("Add Property")
        try:
            property_list1 = self.obj1.get_options("Test")
            property_list1.set_string("A1", "listA1")
        finally:
            self.obj1.end_transaction(tx_id, True)

        tx_id = self.obj2.start_transaction("Add Property")
        try:
            property_list2 = self.obj2.get_options("Test")
            property_list2.set_string("A2", "listA2")
        finally:
            self.obj2.end_transaction(tx_id, True)

    def tearDown(self):
        if self.obj1 is not None:
            self.obj1.release(self)
        if self.obj2 is not None:
            self.obj2.release(self)

    @unittest.skip
    def test_add_synchronized_domain_object(self):

        # Test add synchronized domain object

        assert_null(self.obj1.get_current_transaction())
        assert_null(self.obj2.get_current_transaction())

        assertEquals(1, self.obj1.get_undo_stack_depth())
        assertEquals(1, self.obj2.get_undo_stack_depth())

        assertTrue(self.obj1.can_undo())
        assertTrue(self.obj2.can_undo())
        assertFalse(self.obj1.can_redo())
        assertFalse(self.obj2.can_redo())

        tx = self.obj1_listener.get_last_transaction()
        assert_not_null(tx)

        events = self.obj1_listener.get_events()
        assertEquals(UNDO_STATE_CHANGE1, events[-1])

        tx = self.obj2_listener.get_last_transaction()
        assert_not_null(tx)

        events = self.obj2_listener.get_events()
        assertEquals(UNDO_STATE_CHANGE2, events[-1])

    @unittest.skip
    def test_close_separation(self):

        # Test close separation

        try:
            self.obj1.add_synchronized_domain_object(self.obj2)
        except LockException as e:
            print_stack_trace(e)
            fail(str(e))

        events = self.obj1_listener.get_events()
        assertEquals(UNDO_STATE_CHANGE1, events[-1])

        events = self.obj2_listener.get_events()
        assertEquals(UNDO_STATE_CHANGE2, events[-1])

        self.obj1.release(self)

    def test_rollback_non_committed_transaction(self):

        # Test rollback non-committed transaction

        tx_id1 = self.obj1.start_transaction("Test1")
        try:
            assert_not_null(self.obj2.get_current_transaction())

            property_list1.set_string("A1.B1", "TestB1")

            events = self.obj1_listener.get_events()
            assertEquals(UNDO_STATE_CHANGE1, events[-1])

            tx_id2 = self.obj2.start_transaction("Test2")
            try:
                property_list2.set_string("A2.B2", "TestB2")

                events = self.obj1_listener.get_events()
                assertEquals(START, events[0])
                assertEquals(UNDO_STATE_CHANGE1, events[-1])

                events = self.obj2_listener.get_events()
                assertEquals(START, events[0])
                assertEquals(UNDO_STATE_CHANGE2, events[-1])
            finally:
                self.obj2.end_transaction(tx_id2, True)

            events = self.obj1_listener.get_events()
            assertEquals([], events)
            assertEquals("TestB1", property_list1.get_string("A1.B1", "NULL"))
            assertEquals("TestB2", property_list2.get_string("A2.B2", "NULL"))

        finally:
            self.obj1.end_transaction(tx_id1, False)

    def test_committed_transaction(self):

        # Test committed transaction

        tx_id1 = self.obj1.start_transaction("Test1")
        try:
            assert_not_null(self.obj2.get_current_transaction())

            property_list1.set_string("A1.B1", "TestB1")

            events = self.obj1_listener.get_events()
            assertEquals(START, events[0])
            assertEquals(UNDO_STATE_CHANGE1, events[-1])

            tx_id2 = self.obj2.start_transaction("Test2")
            try:
                property_list2.set_string("A2.B2", "TestB2")

                events = self.obj1_listener.get_events()
                assertEquals([], events)
                assertEquals(START, events[0])
                assertEquals(UNDO_STATE_CHANGE1, events[-1])

                events = self.obj2_listener.get_events()
                assertEquals([], events)
                assertEquals(START, events[0])
                assertEquals(UNDO_STATE_CHANGE2, events[-1])
            finally:
                self.obj2.end_transaction(tx_id2, True)

            events = self.obj1_listener.get_events()
            assertEquals([END], events)
            assertEquals("TestB1", property_list1.get_string("A1.B1", "NULL"))
            assertEquals("TestB2", property_list2.get_string("A2.B2", "NULL"))

        finally:
            self.obj1.end_transaction(tx_id1, True)

    def test_rollback_committed_transaction(self):

        # Test rollback committed transaction

        tx_id1 = self.obj1.start_transaction("Test1")
        try:
            assert_not_null(self.obj2.get_current_transaction())

            property_list1.set_string("A1.B1", "TestB1")

            events = self.obj1_listener.get_events()
            assertEquals(START, events[0])
            assertEquals(UNDO_STATE_CHANGE1, events[-1])

            tx_id2 = self.obj2.start_transaction("Test2")
            try:
                property_list2.set_string("A2.B2", "TestB2")

                events = self.obj1_listener.get_events()
                assertEquals([], events)
                assertEquals(START, events[0])
                assertEquals(UNDO_STATE_CHANGE1, events[-1])

                events = self.obj2_listener.get_events()
                assertEquals([], events)
                assertEquals(START, events[0])
                assertEquals(UNDO_STATE_