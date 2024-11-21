import unittest
from ghidra.app.merge.listing import *
from ghidra.program.database import OriginalProgramModifierListener
from ghidra.program.model.symbol import *

class SymbolMergeManagerNamespace2Test(unittest.TestCase):

    def testRemoveAndRenameNamespaceChooseLatest(self):
        mtf.initialize("NotepadMergeListingTest", OriginalProgramModifierListener())
        
        result_program = None
        result_address_factory = None

        listener = OriginalProgramModifierListener()
        listener.modifyOriginal = lambda program: self.modify_original(program)
        listener.modifyLatest = lambda program: self.modify_latest(program)
        listener.modifyPrivate = lambda program: self.modify_private(program)

        mtf.initialize("NotepadMergeListingTest", listener)

        result_program = mtf.getResultProgram()
        result_address_factory = result_program.getAddressFactory()

        execute_merge(ASK_USER)
        choose_radio_button(LATEST_BUTTON_NAME)
        wait_for_merge_completion()

        symbol_table = result_program.getSymbolTable()
        foo_symbol = symbol_table.getNamespaceSymbol("foo", None)
        bar_symbol = symbol_table.getNamespaceSymbol("bar", None)
        bar_conflict1_namespace = symbol_table.getNamespaceSymbol("bar_.conflict1", None)

        self.assertIsNone(foo_symbol)
        self.assertIsNotNone(bar_symbol)
        self.assertEqual(SymbolType.NAMESPACE, bar_symbol.getSymbolType())
        self.assertIsNone(bar_conflict1_namespace)

    def testRemoveAndRenameNamespaceChooseMy(self):
        mtf.initialize("NotepadMergeListingTest", OriginalProgramModifierListener())

        result_program = None
        result_address_factory = None

        listener = OriginalProgramModifierListener()
        listener.modifyOriginal = lambda program: self.modify_original(program)
        listener.modifyLatest = lambda program: self.modify_latest(program)
        listener.modifyPrivate = lambda program: self.modify_private(program)

        mtf.initialize("NotepadMergeListingTest", listener)

        result_program = mtf.getResultProgram()
        result_address_factory = result_program.getAddressFactory()

        execute_merge(ASK_USER)
        choose_radio_button(CHECKED_OUT_BUTTON_NAME)
        wait_for_merge_completion()

        symbol_table = result_program.getSymbolTable()
        foo_symbol = symbol_table.getNamespaceSymbol("foo", None)
        bar_symbol = symbol_table.getNamespaceSymbol("bar", None)

        self.assertIsNone(foo_symbol)
        self.assertIsNone(bar_symbol)

    def testRenameRemoveNamespaceAndCreateLibChooseLatest(self):
        mtf.initialize("NotepadMergeListingTest", OriginalProgramModifierListener())

        result_program = None
        result_address_factory = None

        listener = OriginalProgramModifierListener()
        listener.modifyOriginal = lambda program: self.modify_original(program)
        listener.modifyLatest = lambda program: self.modify_latest(program)
        listener.modifyPrivate = lambda program: self.modify_private(program)

        mtf.initialize("NotepadMergeListingTest", listener)

        result_program = mtf.getResultProgram()
        result_address_factory = result_program.getAddressFactory()

        execute_merge(ASK_USER)
        choose_radio_button(LATEST_BUTTON_NAME)
        wait_for_merge_completion()

        symbol_table = result_program.getSymbolTable()
        foo_symbol = symbol_table.getNamespaceSymbol("foo", None)
        bar_symbol = symbol_table.getNamespaceSymbol("bar", None)
        baz_library = symbol_table.getLibrarySymbol("baz")

        self.assertIsNone(foo_symbol)
        self.assertIsNotNone(bar_symbol)
        self.assertEqual(SymbolType.NAMESPACE, bar_symbol.getSymbolType())
        self.assertIsNone(baz_library)

    def testRenameRemoveNamespaceAndCreateLibChooseMy(self):
        mtf.initialize("NotepadMergeListingTest", OriginalProgramModifierListener())

        result_program = None
        result_address_factory = None

        listener = OriginalProgramModifierListener()
        listener.modifyOriginal = lambda program: self.modify_original(program)
        listener.modifyLatest = lambda program: self.modify_latest(program)
        listener.modifyPrivate = lambda program: self.modify_private(program)

        mtf.initialize("NotepadMergeListingTest", listener)

        result_program = mtf.getResultProgram()
        result_address_factory = result_program.getAddressFactory()

        execute_merge(ASK_USER)
        choose_radio_button(CHECKED_OUT_BUTTON_NAME)
        wait_for_merge_completion()

        symbol_table = result_program.getSymbolTable()
        foo_symbol = symbol_table.getNamespaceSymbol("foo", None)
        bar_symbol = symbol_table.getNamespaceSymbol("bar", None)

        self.assertIsNone(foo_symbol)
        self.assertIsNone(bar_symbol)

    def testRemoveAndRenameNamespaceRemoveCheckedOut(self):
        mtf.initialize("NotepadMergeListingTest", OriginalProgramModifierListener())

        result_program = None
        result_address_factory = None

        listener = OriginalProgramModifierListener()
        listener.modifyOriginal = lambda program: self.modify_original(program)
        listener.modifyLatest = lambda program: self.modify_latest(program)
        listener.modifyPrivate = lambda program: self.modify_private(program)

        mtf.initialize("NotepadMergeListingTest", listener)

        result_program = mtf.getResultProgram()
        result_address_factory = result_program.getAddressFactory()

        execute_merge(ASK_USER)
        choose_radio_button(REMOVE_CHECKED_OUT_BUTTON_NAME)
        wait_for_merge_completion()

        symbol_table = result_program.getSymbolTable()
        foo_symbol = symbol_table.getNamespaceSymbol("foo", None)

        self.assertIsNone(foo_symbol)

    def testRemoveAndRenameNamespaceRenameCheckedOut(self):
        mtf.initialize("NotepadMergeListingTest", OriginalProgramModifierListener())

        result_program = None
        result_address_factory = None

        listener = OriginalProgramModifierListener()
        listener.modifyOriginal = lambda program: self.modify_original(program)
        listener.modifyLatest = lambda program: self.modify_latest(program)
        listener.modifyPrivate = lambda program: self.modify_private(program)

        mtf.initialize("NotepadMergeListingTest", listener)

        result_program = mtf.getResultProgram()
        result_address_factory = result_program.getAddressFactory()

        execute_merge(ASK_USER)
        choose_radio_button(RENAME_CHECKED_OUT_BUTTON_NAME)
        wait_for_merge_completion()

        symbol_table = result_program.getSymbolTable()
        foo_symbol = symbol_table.getNamespaceSymbol("foo", None)

        self.assertIsNone(foo_symbol)

    def testRenameNamespaceVsAddLibrary(self):
        mtf.initialize("NotepadMergeListingTest", OriginalProgramModifierListener())

        result_program = None
        result_address_factory = None

        listener = OriginalProgramModifierListener()
        listener.modifyOriginal = lambda program: self.modify_original(program)
        listener.modifyLatest = lambda program: self.modify_latest(program)
        listener.modifyPrivate = lambda program: self.modify_private(program)

        mtf.initialize("NotepadMergeListingTest", listener)

        result_program = mtf.getResultProgram()
        result_address_factory = result_program.getAddressFactory()

        execute_merge(ASK_USER)
        wait_for_merge_completion()

        symbol_table = result_program.getSymbolTable()
        foo_symbol = symbol_table.getNamespaceSymbol("foo", None)
        bar_symbol = symbol_table.getNamespaceSymbol("bar", None)

        self.assertIsNone(foo_symbol)
        self.assertIsNotNone(bar_symbol)
        self.assertEqual(SymbolType.NAMESPACE, bar_symbol.getSymbolType())

    def modify_original(self, program):
        tx_id = program.startTransaction("Modify Original Program")
        try:
            symtab = program.getSymbolTable()
            symtab.createNameSpace(program.getGlobalNamespace(), "foo", SourceType.USER_DEFINED)
        finally:
            program.endTransaction(tx_id, True)

    def modify_latest(self, program):
        tx_id = program.startTransaction("Modify Latest Program")
        try:
            symtab = program.getSymbolTable()
            namespace_symbol = symtab.getNamespaceSymbol("foo", None)
            namespace_symbol.setName("bar", SourceType.USER_DEFINED)
        finally:
            program.endTransaction(tx_id, True)

    def modify_private(self, program):
        tx_id = program.startTransaction("Modify My Program")
        try:
            program.getExternalManager().addExternalLibraryName("bar", SourceType.USER_DEFINED)
        finally:
            program.endTransaction(tx_id, True)


if __name__ == "__main__":
    unittest.main()
