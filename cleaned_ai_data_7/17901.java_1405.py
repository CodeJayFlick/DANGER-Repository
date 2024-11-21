import unittest
from io import StringIO
from collections import defaultdict

class MetaUtilsTest(unittest.TestCase):

    def test_split_path_to_nodes(self):
        self.assertEqual(
            ["root", "sg", "d1", "s1"],
            MetaUtils.split_path_to_detached_path("root.sg.d1.s1")
        )

        self.assertEqual(
            ["root", "sg", "d1", "\"s.1\""],
            MetaUtils.split_path_to_detached_path("root.sg.d1.\"s.1\"")
        )

        self.assertEqual(
            ["root", "sg", "d1", "\"s\\\".1\""],
            MetaUtils.split_path_to_detached_path("root.sg.d1.\"s\\\".1\"")
        )

        self.assertEqual(
            ["root", "\"s g\"", "d1", "\"s.1\""],
            MetaUtils.split_path_to_detached_path("root.\"s g\".d1.\"s.1\"")
        )

        self.assertEqual(
            ["root", "\"s g\"", "\"d_.1\"", "\"s.1.1\""],
            MetaUtils.split_path_to_detached_path("root.\"s g\".\"d_.1\".\"s.1.1\"")
        )

        self.assertEqual(["root"], MetaUtils.split_path_to_detached_path("root"))

        self.assertEqual(
            ["root", "sg", "d1", "s", "1"],
            MetaUtils.split_path_to_detached_path("root.sg.d1.s.1")
        )

        try:
            MetaUtils.split_path_to_detached_path("root.sg.\"d.1\"\"s.1\"")
            self.fail()
        except ValueError as e:
            self.assertEqual(
                "root.sg.\"d.1\"\"s.1\" is not a legal path",
                str(e)
            )

        try:
            MetaUtils.split_path_to_detached_path("root..a")
            self.fail()
        except ValueError as e:
            self.assertEqual(
                "root..a is not a legal path", 
                str(e) 
            ) 

        try:  
            MetaUtils.split_path_to_detached_path("root.sg.d1.'s1'")
            self.fail()   
        except ValueError as e:    
            self.assertEqual(  
                "root.sg.d1.'s1' is not a legal path",
                str(e)
            )

        try:
            MetaUtils.split_path_to_detached_path("root.sg.d1.")
            self.fail()
        except ValueError as e:
            self.assertEqual(
                "root.sg.d1. is not a legal path", 
                str(e) 
            ) 

    def test_get_multi_full_paths(self):
        root_node = InternalMNode(None, "root")

        # builds the relationship of root.a and root.aa
        a_node = InternalMNode(root_node, "a")
        root_node.add_child(a_node.name, a_node)
        aa_node = InternalMNode(root_node, "aa")
        root_node.add_child(aa_node.name, aa_node)

        # builds the relationship of root.a.b and root.aa.bb
        b_node = InternalMNode(a_node, "b")
        a_node.add_child(b_node.name, b_node)
        bb_node = InternalMNode(aa_node, "bb")
        aa_node.add_child(bb_node.name, bb_node)

        # builds the relationship of root.aa.bb.cc
        cc_node = InternalMNode(bb_node, "cc")
        bb_node.add_child(cc_node.name, cc_node)

        multi_full_paths = MetaUtils.get_multi_full_paths(root_node)
        self.assertEqual(2, len(multi_full_paths))

        for path in multi_full_paths:
            if "\"aa\"\".bb.\".cc" in path:
                self.assertEqual("\"root.aa.bb.cc\"", path)
            else:
                self.assertEqual("\"root.a.b\"", path)

if __name__ == '__main__':
    unittest.main()
