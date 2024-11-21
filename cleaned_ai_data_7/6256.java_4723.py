import unittest
from ghidra_framework import *
from ghidra_program_database import *

class BookmarkEditCmdTest(unittest.TestCase):

    def setUp(self):
        self.notepad = build_program()
        self.bookmark_manager = self.notepad.get_bookmark_manager()
        self.location_generator = SampleLocationGenerator(self.notepad)

    def build_program(self):
        builder = ProgramBuilder("Test", _TOY)
        builder.create_memory("test1", "0x1001000", 0x2000)
        return builder.get_program()

    def create_bookmarks(self, locs):
        compound_cmd = CompoundCmd("Create Bookmarks")

        addrs = []
        for i in range(len(locs)):
            addr = locs[i].get_address()
            cmd = BookmarkEditCmd(addr, "Type" + str(i), "Cat" + str(i), "Cmt" + str(i))
            compound_cmd.add(cmd)
            addrs.append(addr)

        apply_cmd(self.notepad, compound_cmd)
        print("Created", len(addrs), "Bookmarks")
        return addrs

    def get_bookmarks(self, mgr):
        list = []
        it = mgr.get_bookmarks_iterator()
        while it.has_next():
            list.append(it.next())
        return list

    @unittest.skip
    def test_create_bookmark_on_addr(self):

        orig_type_cnt = self.bookmark_manager.get BookmarkTypes().length
        original_list = get_bookmarks(self.bookmark_manager)

        addrs = create_bookmarks(self.location_generator.get_program_locations())

        self.assertEqual(orig_type_cnt + len(addrs), self.bookmark_manager.get BookmarkTypes().length)
        list = get_bookmarks(self.bookmark_manager)
        self.assertEqual(original_list.size() + len(addrs), list.size())
        iter = list.iterator()
        while iter.has_next():
            bm = iter.next()
            if original_list.contains(bm):
                continue
            ix = addrs.index(bm.get_address())
            addrs[ix] = None
            self.assertEqual("Type" + str(ix), bm.type_string)
            self.assertEqual("Cat" + str(ix), bm.category)
            self.assertEqual("Cmt" + str(ix), bm.comment)

    @unittest.skip
    def test_create_bookmark_on_addr_set(self):

        set = AddressSet()
        set.add(builder.addr("0x1001000"), builder.addr("0x10010010"))
        set.add(builder.addr("0x1002000"), builder.addr("0x10020010"))
        set.add(builder.addr("0x1003000"), builder.addr("0x10030010"))
        set.add(builder.addr("0x1004000"), builder.addr("0x10040010"))

        cmd = BookmarkEditCmd(set, "Type0", "Cat0", "Cmt0")
        apply_cmd(self.notepad, cmd)

        iter = set.get_address_ranges()
        cnt = 0
        while iter.has_next():
            range = iter.next()
            cnt += 1

            bm = self.bookmark_manager.get Bookmark(range.min_address(), "Type0", "Cat0")
            assert not bm is None
            self.assertEqual("Cmt0", bm.comment)

        self.assertEqual(cnt, self.bookmark_manager.get BookmarkCount("Type0"))

    @unittest.skip
    def test_edit_bookmark(self):

        addrs = create_bookmarks(self.location_generator.get_program_locations())
        bm_cnt = get_bookmarks(self.bookmark_manager).size()

        bm = self.bookmark_manager.get Bookmark(addrs[0], "Type0", "Cat0")
        assert not bm is None

        cmd = BookmarkEditCmd(bm, "CatX", "CmtX")
        apply_cmd(self.notepad, cmd)

        self.assertEqual(bm_cnt, get_bookmarks(self.bookmark_manager).size())

        self.assertIsNone(self.bookmark_manager.get Bookmark(addrs[0], "Type0", "Cat0"))

        bm = self.bookmark_manager.get Bookmark(addrs[0], "Type0", "CatX")
        assert not bm is None
        self.assertEqual("CatX", bm.category)
        self.assertEqual("CmtX", bm.comment)

    @unittest.skip
    def test_create_bookmark_on_addr_with_undo(self):

        orig_type_cnt = self.bookmark_manager.get BookmarkTypes().length
        original_list = get_bookmarks(self.bookmark_manager)
        original_cnt = original_list.size()

        addrs = create_bookmarks(self.location_generator.get_program_locations())

        self.assertEqual(orig_type_cnt + len(addrs), self.bookmark_manager.get BookmarkTypes().length)

        self.notepad.undo()
        self.assertEqual(original_cnt, self.bookmark_manager.get BookmarkCount())


if __name__ == '__main__':
    unittest.main()
