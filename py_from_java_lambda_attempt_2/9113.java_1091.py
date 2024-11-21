Here is the translation of the Java code into Python:

```Python
import random
from abc import ABCMeta, abstractmethod

class VTMarkupItemResetTest:
    def __init__(self):
        self.test_transaction_id = None
        self.association_dbm = None

    @staticmethod
    def create_random_match(db):
        # implementation of this method is missing in the Java code
        pass

    @staticmethod
    def create_program_correlator(null, source_program, destination_program):
        # implementation of this method is missing in the Java code
        pass

    @staticmethod
    def get_stored_markup_items(association):
        markup_item_manager = association.get_instance_field("markupManager")
        return invoke_instance_method("getStoredMarkupItems", 
                                       markup_item_manager, [TaskMonitorAdapter.DUMMY_MONITOR])

    @staticmethod
    def create_random_apply_action(item):
        action_type = random.choice(list(VTMarkupItemApplyActionType))
        while not item.supports_apply_action(action_type):
            action_type = random.choice(list(VTMarkupItemApplyActionType))
        return action_type

    def setUp(self):
        super().setUp()
        self.association_dbm = db.get_association_manager_dbm()
        self.test_transaction_id = db.start_transaction("Test Match Set Setup")

    def tearDown(self):
        db.end_transaction(self.test_transaction_id, False)
        db.release(VTTestUtils)

    @staticmethod
    def get_random_int(min_value, max_value):
        return random.randint(min_value, max_value)

    # Test that the markup item storage is removed (reset) from the DB when the destination address is cleared and not other user-defined values are set.
    def test_db_markup_item_storage_reset_clear_destination_address(self):
        match_set = db.create_match_set(create_program_correlator(None, db.get_source_program(), db.get_destination_program()))
        match = match_set.add_match(db.create_random_match(db))
        markup_item = create_random_markup_item_stub(match)
        association = match.get_association()
        destination_address = addr()
        unapplied_markup_item = markup_item

        unapplied_markup_item.set_destination_address(destination_address)

        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 1)

        unapplied_markup_item.set_destination_address(None)
        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 0)

    # Test that the markup item storage is removed (reset) from the DB when the user's considered state is cleared and not other user-defined values are set.
    def test_db_markup_item_storage_reset_clear_considered(self):
        match_set = db.create_match_set(create_program_correlator(None, db.get_source_program(), db.get_destination_program()))
        match = match_set.add_match(db.create_random_match(db))
        markup_item = create_random_markup_item_stub(match)
        association = match.get_association()
        unapplied_markup_item = markup_item

        unapplied_markup_item.set_considered(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE)

        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 1)

        unapplied_markup_item.set_considered(VTMarkupItemConsideredStatus.UNCONSIDERED)
        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 0)

    # Test that the markup item storage is removed (reset) from the DB when the markup item is unapplied and not other user-defined values are set.
    def test_db_markup_item_storage_reset_unapply(self):
        match_set = db.create_match_set(create_program_correlator(None, db.get_source_program(), db.get_destination_program()))
        match = match_set.add_match(db.create_random_match(db))
        markup_item = create_random_markup_item_stub(match)
        association = match.get_association()
        destination_address = addr()
        unapplied_markup_item = markup_item

        unapplied_markup_item.set_default_destination_address(destination_address, "Test Source")

        try:
            association.set_accepted()
            unapplied_markup_item.apply(create_random_apply_action(unapplied_markup_item), None)
        except (VersionTrackingApplyException, VTAssociationStatusException):
            self.fail("Unexpected exception applying a test markup item")

        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 1)

        try:
            unapplied_markup_item.unapply()
        except VersionTrackingApplyException:
            self.fail("Unexpected exception unapplying a test markup item")

        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 0)

    # Test that the markup item storage is not removed when the destination address is set by the user.
    def test_db_markup_item_storage_reset_doesnt_happen_unapply(self):
        match_set = db.create_match_set(create_program_correlator(None, db.get_source_program(), db.get_destination_program()))
        match = match_set.add_match(db.create_random_match(db))
        markup_item = create_random_markup_item_stub(match)
        association = match.get_association()
        destination_address = addr()
        unapplied_markup_item = markup_item

        # 1) Set an address - this will prevent a reset
        unapplied_markup_item.set_destination_address(destination_address)

        try:
            unapplied_markup_item.apply(create_random_apply_action(unapplied_markup_item), None)
        except (VersionTrackingApplyException, VTAssociationStatusException):
            self.fail("Unexpected exception applying a test markup item")

        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 1)

        try:
            unapplied_markup_item.unapply()
        except VersionTrackingApplyException:
            self.fail("Unexpected exception unapplying a test markup item")

        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 0)

    # Test that the markup item storage is not removed when the considered status was set.
    def test_db_markup_item_storage_reset_doesnt_happen_clear_considered(self):
        match_set = db.create_match_set(create_program_correlator(None, db.get_source_program(), db.get_destination_program()))
        match = match_set.add_match(db.create_random_match(db))
        markup_item = create_random_markup_item_stub(match)
        association = match.get_association()
        destination_address = addr()
        unapplied_markup_item = markup_item

        # 1) Set a considered status - this will prevent a reset
        unapplied_markup_item.set_considered(VTMarkupItemConsideredStatus.IGNORE_DONT_KNOW)

        unapplied_markup_item.set_destination_address(destination_address)

        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 1)

        unapplied_markup_item.set_destination_address(None)

        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 0)

    # Test that the markup item storage is not removed when the destination address was cleared.
    def test_db_markup_item_storage_reset_doesnt_happen_clear_destination_address(self):
        match_set = db.create_match_set(create_program_correlator(None, db.get_source_program(), db.get_destination_program()))
        match = match_set.add_match(db.create_random_match(db))
        markup_item = create_random_markup_item_stub(match)
        association = match.get_association()
        destination_address = addr()
        unapplied_markup_item = markup_item

        # 1) Set a considered status - this will prevent a reset
        unapplied_markup_item.set_considered(VTMarkupItemConsideredStatus.IGNORE_DONT_KNOW)

        unapplied_markup_item.set_destination_address(destination_address)

        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 1)

        unapplied_markup_item.set_destination_address(None)

        stored_markup_items = get_stored_markup_items(association)
        self.assertEqual(len(stored_markup_items), 0)