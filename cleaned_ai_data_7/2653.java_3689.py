import unittest
from ghidra_trace_database_bookmark import DBTraceBookmarkManager
from ghidra_trace_model_thread import TraceThread
from ghidra_util_database_undoable_transaction import UndoableTransaction


class TestDBTraceBookmarkManager(unittest.TestCase):

    def setUp(self):
        self.b = ToyDBTraceBuilder("Testing", "Toy:BE:64:default")
        self.manager = self.b.trace.get_bookmark_manager()

    def tearDown(self):
        self.b.close()

    def test_define_bookmark_type(self):
        assert self.manager.get_bookmark_type("Test Type") is None
        bookmark_types = set(self.manager.get_defined_bookmark_types())
        self.assertEqual(bookmark_types, set())

        bookmark_type = self.b.get_or_add_bookmark_type("Test Type")
        self.assertEqual(self.manager.get_bookmark_type("Test Type"), bookmark_type)
        bookmark_types = set(self.manager.get_defined_bookmark_types())
        self.assertEqual(bookmark_types, {bookmark_type})

    def test_get_bookmark_by_id(self):
        bookmark = self.manager.get_bookmark(0)
        assert bookmark is None

        with UndoableTransaction() as tid:
            bookmark = self.b.add_bookmark(0, 0, "Test Type", "Cat1", "Test comment")
        id = bookmark.id

        found_bookmark = self.manager.get_bookmark(id)
        self.assertEqual(bookmark, found_bookmark)

    def test_delete_bookmark(self):
        with UndoableTransaction() as tid:
            bookmark = self.b.add_bookmark(0, 0, "Test Type", "Cat1", "Test comment")
        id = bookmark.id

        with UndoableTransaction() as tid:
            bookmark.delete()
        found_bookmark = self.manager.get_bookmark(id)
        assert found_bookmark is None

    def test_get_register_bookmark_by_id(self):
        try:
            with UndoableTransaction() as tid:
                bookmark = self.b.add_register_bookmark(0, "Thread1", "r4", "Test Type", "Cat1", "Test comment")
            id = bookmark.id
            found_bookmark = self.manager.get_bookmark(id)
            self.assertEqual(bookmark, found_bookmark)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_get_categories_for_type(self):
        try:
            with UndoableTransaction() as tid:
                thread = self.b.trace.create_thread("Thread1", 0)
                register_space = self.manager.get_register_space(thread, True)

                bookmark_type = self.b.get_or_add_bookmark_type("Test Type")
                assert set(bookmark_type.categories) == set()
                assert set(self.manager.get_categories_for_type(bookmark_type)) == set()

                self.assertEqual(set(register_space.get_categories_for_type(bookmark_type)), set())

                with UndoableTransaction() as tid:
                    self.b.add_bookmark(0, 0, "Test Type", "Cat1", "First")
                self.assertEqual(set(bookmark_type.categories), {"Cat1"})
                self.assertEqual(set(self.manager.get_categories_for_type(bookmark_type)), {"Cat1"})

                with UndoableTransaction() as tid:
                    self.b.add_register_bookmark(0, "Thread1", "r4", "Test Type", "Cat2", "Second")
                self.assertEqual(set(bookmark_type.categories), {"Cat1", "Cat2"})
                self.assertEqual(set(self.manager.get_categories_for_type(bookmark_type)), {"Cat1"})

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_get_bookmarks_for_type(self):
        try:
            with UndoableTransaction() as tid:
                bookmark_type = self.b.get_or_add_bookmark_type("Test Type")
                assert not bookmark_type.has_bookmarks()
                self.assertEqual(bookmark_type.count_bookmarks(), 0)

                with UndoableTransaction() as tid:
                    bookmark1 = self.b.add_bookmark(0, 0, "Test Type", "Cat1", "First")
                self.assertTrue(bookmark_type.has_bookmarks())
                self.assertEqual(bookmark_type.count_bookmarks(), 1)
                self.assertEqual(set(bookmark_type.get_bookmarks()), {bookmark1})

                with UndoableTransaction() as tid:
                    bookmark2 = self.b.add_register_bookmark(0, "Thread1", "r4", "Test Type", "Cat2", "Second")
                self.assertTrue(bookmark_type.has_bookmarks())
                self.assertEqual(bookmark_type.count_bookmarks(), 2)
                self.assertEqual(set(bookmark_type.get_bookmarks()), {bookmark1, bookmark2})

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_get_all_bookmarks(self):
        try:
            with UndoableTransaction() as tid:
                bookmark1 = self.b.add_bookmark(0, 0, "Test Type", "Cat1", "First")
                bookmark2 = self.b.add_bookmark(1, 4, "Test Type", "Cat2", "Second")

            self.assertEqual(set(self.manager.get_all_bookmarks()), {bookmark1, bookmark2})

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_get_bookmarks_at(self):
        try:
            with UndoableTransaction() as tid:
                bookmark1 = self.b.add_bookmark(0, 0, "Test Type", "Cat1", "First")
                bookmark2 = self.b.add_bookmark(1, 4, "Test Type", "Cat2", "Second")

            self.assertEqual(set(self.manager.get_bookmarks_at(0, self.b.addr(1))), set())
            self.assertEqual(set(self.manager.get_bookmarks_at(0, self.b.addr(0))), {bookmark1})
            self.assertEqual(set(self.manager.get_bookmarks_at(1, self.b.addr(4))), {bookmark2})

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_get_bookmarks_enclosed(self):
        try:
            with UndoableTransaction() as tid:
                bookmark1 = self.b.add_bookmark(0, 0, "Test Type", "Cat1", "First")
                bookmark2 = self.b.add_bookmark(1, 4, "Test Type", "Cat2", "Second")

            self.assertEqual(set(self.manager.get_bookmarks_enclosed(Range.closed(0L, 10L), self.b.range(0, 0x10))), set())
            self.assertEqual(set(self.manager.get_bookmarks_enclosed(Range.at_least(0L), self.b.range(0, 3))), {bookmark1})
            self.assertEqual(set(self.manager.get_bookmarks_enclosed(Range.at_least(0L), self.b.range(2, 5))), {bookmark2})
            self.assertEqual(set(self.manager.get_bookmarks_enclosed(Range.at_least(0L), self.b.range(0, 0x10))), {bookmark1, bookmark2})

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_get_bookmarks_intersecting(self):
        try:
            with UndoableTransaction() as tid:
                bookmark1 = self.b.add_bookmark(0, 0, "Test Type", "Cat1", "First")
                bookmark2 = self.b.add_bookmark(1, 4, "Test Type", "Cat2", "Second")

            self.assertEqual(set(self.manager.get_bookmarks_intersecting(Range.closed(2L, 4L), self.b.range(1, 3))), set())
            self.assertEqual(set(self.manager.get_bookmarks_intersecting(Range.closed(0L, 0L), self.b.range(0, 0x10))), {bookmark1})
            self.assertEqual(set(self.manager.get_bookmarks_intersecting(Range.closed(0L, 10L), self.b.range(2, 5))), {bookmark2})
            self.assertEqual(set(self.manager.get_bookmarks_intersecting(Range.closed(0L, 10L), self.b.range(0, 0x10))), {bookmark1, bookmark2})

        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == '__main__':
    unittest.main()
