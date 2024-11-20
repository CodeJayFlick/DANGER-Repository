import unittest
from ghidra_feature_vt_api import VTSessionDB, VTMatch, EolCommentMarkupType, ApplyMarkupItemTask
from ghidra_program_model_listing import CodeUnit
from util_task import TaskMonitor

class ApplyMultipleMarkupItemsTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.source_builder.create_comment("1002248", "Comment 1", CodeUnit.EOL_COMMENT)
        self.source_builder.create_comment("100224b", "Comment 2", CodeUnit.EOL_COMMENT)
        self.source_program = self.source_builder.get_program()

    def test_apply_multiple_markup_items_some_good_some_bad(self):
        session = create_new_session()
        match = create_match_set_with_one_match(session, addr("1002239", self.source_program), 
            addr("1002239", destination_program))
        items = EolCommentMarkupType.INSTANCE.create_markup_items(match.get_association())

        # make the first item have an illegal destination address and then make sure the other
        # one still gets applied using the ApplyMarkupTask

        id = session.start_transaction("test")

        items[0].set_destination_address(addr("0x100224c", destination_program))

        task = ApplyMarkupItemTask(session, items, VTOptions("Test"))
        task.run(TaskMonitor.DUMMY)
        session.end_transaction(id, True)

        self.assertTrue(task.was_successful())
        self.assertTrue(task.has_errors())

if __name__ == "__main__":
    unittest.main()
