Here is the translation of the Java code into Python:

```Python
import random
from collections import Collection

class VTMatchSetDBTest:
    def __init__(self):
        self.transaction_id = None

    def setUp(self):
        # super().setUp()
        pass  # Not implemented in this example, but would typically be used to set up any necessary state or resources.

    def tearDown(self):
        if self.transaction_id is not None:
            db.end_transaction(self.transaction_id, False)
        else:
            print("No transaction ID found. Skipping end of transaction.")

    @staticmethod
    def create_program_correlator(source_program=None, destination_program=None):
        # This method would typically be implemented to create a VTProgramCorrelator object.
        pass  # Not implemented in this example.

    def test_add_match(self):
        correlator = self.create_program_correlator()
        match_set = db.create_match_set(correlator)
        assert match_set is not None

        match_info = self.create_random_match(db)
        match_set.add_match(match_info)

        matches = match_set.get_matches()
        assert len(matches) == 1
        match_from_db = next(iter(matches))
        self.assert_equivalent("Match put into DB is not the same as the match we got back", match_info, match_from_db)

    def test_reject_available_match(self):
        correlator = self.create_program_correlator()
        match_set = db.create_match_set(correlator)
        assert match_set is not None

        match_info = self.create_match(match_set)
        db_match = match_set.add_match(match_info)
        association_db = db_match.get_association()
        set_instance_field("markup_manager", association_db, new_markup_item_manager_impl_dummy(association_db))

        assert_equal(VTAssociationStatus.AVAILABLE, db_match.get_association().get_status())
        self.assert_equivalent("Match put into DB is not the same as the match we got back", match_info, db_match)

        matches = match_set.get_matches()
        assert len(matches) == 1
        match_from_db = next(iter(matches))
        set_instance_field("association", match_from_db.get_association(), VTAssociationStatus.IGNORED)
        self.assert_equivalent("Match put into DB is not the same as the match we got back", match_info, match_from_db)

    def test_reject_accepted_match_failure(self):
        correlator = self.create_program_correlator()
        match_set = db.create_match_set(correlator)
        assert match_set is not None

        match_info = self.create_match(match_set)
        db_match = match_set.add_match(match_info)
        association_db = db_match.get_association()
        set_instance_field("markup_manager", association_db, new_markup_item_manager_impl_dummy(association_db))

        assert_equal(VTAssociationStatus.AVAILABLE, db_match.get_association().get_status())
        self.assert_equivalent("Match put into DB is not the same as the match we got back", match_info, db_match)

        matches = match_set.get_matches()
        assert len(matches) == 1
        match_from_db = next(iter(matches))
        set_instance_field("association", match_from_db.get_association(), VTAssociationStatus.ACCEPTED)
        self.assert_equivalent("Match put into DB is not the same as the match we got back", match_info, match_from_db)

        try:
            match_from_db.get_association().set_rejected()
            assert False  # Expected exception when rejected accepted association
        except VTAssociationStatusException:
            pass

    def test_reject_blocked_match(self):
        correlator = self.create_program_correlator()
        match_set = db.create_match_set(correlator)
        assert match_set is not None

        locked_out_match = self.create_locked_out_match(match_set)

        set_instance_field("association", locked_out_match.get_association(), VTAssociationStatus.IGNORED)

        matches = match_set.get_matches(locked_out_match.get_association())
        assert len(matches) == 1
        match_from_db = next(iter(matches))
        self.assert_equivalent("Match put into DB is not the same as the match we got back", locked_out_match, match_from_db)
        set_instance_field("association", match_from_db.get_association(), VTAssociationStatus.IGNORED)

    def assert_equivalent(self, failure_message, info, match):
        association = match.get_association()
        self.assertTrue(failure_message,
            info.source_address == association.source_address and
            info.destination_address == association.destination_address and
            info.confidence_score == match.confidence_score and
            info.destination_length == match.destination_length and
            info.similarity_score == match.similarity_score and
            info.source_length == match.source_length)

    def create_match(self, match_set):
        # This method would typically be implemented to create a VTMatchInfo object.
        pass  # Not implemented in this example.

    @staticmethod
    def new_markup_item_manager_impl_dummy(association_db):
        return MarkupItemManagerImplDummy(association_db)


class MarkupItemManagerImplDummy:
    def __init__(self, association_db):
        super().__init__(association_db)

    def get_generated_markup_items(self, monitor=None):
        return Collection()


def main():
    test = VTMatchSetDBTest()
    test.setUp()
    try:
        test.test_add_match()
        test.test_reject_available_match()
        test.test_reject_accepted_match_failure()
        test.test_reject_blocked_match()
    finally:
        test.tearDown()

if __name__ == "__main__":
    main()


# Helper functions
def set_instance_field(field_name, instance, value):
    setattr(instance, field_name, value)


def get_random_int():
    return random.randint(0, 100)


def addr():
    # This method would typically be implemented to generate a unique address.
    pass  # Not implemented in this example.


def create_match_set(correlator=None):
    # This method would typically be implemented to create a VTMatchSet object.
    pass  # Not implemented in this example.

# Helper classes
class VTScore:
    def __init__(self, value):
        self.value = value

    @property
    def score(self):
        return self.value


def get_random_tag(db=None):
    # This method would typically be implemented to generate a random tag.
    pass  # Not implemented in this example.

# Helper methods
def create_locked_out_match(match_set):
    match_info = self.create_match(match_set)
    db_match = match_set.add_match(match_info)
    association_db = db_match.get_association()
    set_instance_field("markup_manager", association_db, new_markup_item_manager_impl_dummy(association_db))

    related_match = self.create_match(match_set)
    related_match.source_address = db_match.get_association().source_address
    db_related_match = match_set.add_match(related_match)
    related_association_db = db_related_match.get_association()
    set_instance_field("markup_manager", related_association_db, new_markup_item_manager_impl_dummy(related_association_db))
    related_association_db.set_accepted()

    matches2 = ((VTMatchSetDB)match_set).get_matches(db_match.get_association())
    assert len(matches2) == 1
    match_from_db2 = next(iter(matches2))
    association2 = match_from_db2.get_association()
    applied_status2 = association2.get_status()
    self.assertEqual(VTAssociationStatus.BLOCKED, applied_status2)
    return db_match

# Helper classes
class VTMatchInfo:
    def __init__(self):
        pass  # Not implemented in this example.

    @property
    def source_address(self):
        pass  # Not implemented in this example.

    @source_address.setter
    def source_address(self, value):
        self._source_address = value

    @property
    def destination_address(self):
        pass  # Not implemented in this example.

    @destination_address.setter
    def destination_address(self, value):
        self._destination_address = value

    @property
    def confidence_score(self):
        pass  # Not implemented in this example.

    @confidence_score.setter
    def confidence_score(self, value):
        self._confidence_score = value

    @property
    def source_length(self):
        pass  # Not implemented in this example.

    @source_length.setter
    def source_length(self, value):
        self._source_length = value

    @property
    def destination_length(self):
        pass  # Not implemented in this example.

    @destination_length.setter
    def destination_length(self, value):
        self._destination_length = value