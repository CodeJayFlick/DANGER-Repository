Here is the translation of the given Java code into Python:

```Python
import unittest
from collections import defaultdict

class GdbArmDebuggerMappingOpinionTest(unittest.TestCase):

    def test_query_opinions_includes_arm_ldefs_based(self):
        model = TestDebuggerObjectModel()
        
        model.session.environment.change_attributes({
            "_debugger": "gdb",
            "_arch": "armv7",
            "_endian": "little"
        }, "Testing")

        process = model.add_process(1234)

        offers = DebuggerMappingOpinion.query_opinions(process, False)
        self.assertFalse(offers.empty())
        
        ldefs_ones = set()
        for offer in offers:
            if isinstance(offer, GdbArmOffer):
                ldefs_ones.add(offer.get_trace_language_id())

        self.assertFalse(ldefs_ones.empty())
        self.assertTrue(any(id == LanguageID("ARM:LE:32:v7") for id in ldfs_ones))

    def test_query_opinions_excludes_arm_ldefs_based(self):
        model = TestDebuggerObjectModel()
        
        model.session.environment.change_attributes({
            "_debugger": "gdb",
            "_arch": "i386:x86-64:intel",
            "_endian": "little"
        }, "Testing")

        process = model.add_process(1234)

        offers = DebuggerMappingOpinion.query_opinions(process, False)
        self.assertFalse(offers.empty())
        
        ldefs_ones = set()
        for offer in offers:
            if isinstance(offer, GdbArmOffer):
                ldfs_ones.add(offer.get_trace_language_id())

        self.assertTrue(ldefs_ones.empty())

    def test_query_opinions_includes_aarch64_ldefs_based(self):
        model = TestDebuggerObjectModel()
        
        model.session.environment.change_attributes({
            "_debugger": "gdb",
            "_arch": "aarch64",
            "_endian": "little"
        }, "Testing")

        process = model.add_process(1234)

        offers = DebuggerMappingOpinion.query_opinions(process, False)
        self.assertFalse(offers.empty())
        
        ldefs_ones = set()
        for offer in offers:
            if isinstance(offer, GdbAArch64Offer):
                ldfs_ones.add(offer.get_trace_language_id())

        self.assertFalse(ldfs_ones.empty())
        self.assertTrue(any(id == LanguageID("AARCH64:LE:64:v8A") for id in ldfs_ones))

if __name__ == '__main__':
    unittest.main()
```

Note that this Python code is not a direct translation of the Java code. It's more like an equivalent implementation using Python syntax and semantics.