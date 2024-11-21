import unittest
from ghidra_framework_options import ToolOptions
from ghidra_util import SpyErrorLogger, Msg
from docking_tool_constants import DockingToolConstants

class SharedKeyBindingDockingActionTest(unittest.TestCase):

    NON_SHARED_NAME = "Non-Shared Action Name"
    SHARED_NAME = "Shared Action Name"
    SHARED_OWNER = "Shared Owner"

    DEFAULT_KS_1 = {"vk": 65, "modifiers": []}
    DEFAULT_KS_DIFFERENT_THAN_1 = {"vk": 66, "modifiers": []}

    OWNER_1 = "Owner1"
    OWNER_2 = "Owner2"

    def setUp(self):
        self.tool = FakeDockingTool()
        Msg.setErrorLogger(SpyErrorLogger())

    @unittest.skip("Test is not implemented")
    def testSharedKeyBinding_SameDefaultKeyBindings(self):

        action1 = SharedNameAction(OWNER_1, DEFAULT_KS_1)
        action2 = SharedNameAction(OWNER_2, DEFAULT_KS_1)

        self.tool.addAction(action1)
        self.tool.addAction(action2)

        assertNoLoggedMessages()
        assertKeyBinding(action1, DEFAULT_KS_1)
        assertKeyBinding(action2, DEFAULT_KS_1)
        assertSharedStubInTool()

    @unittest.skip("Test is not implemented")
    def testSharedKeyBinding_OptionsChange(self):

        action1 = SharedNameAction(OWNER_1, DEFAULT_KS_1)
        action2 = SharedNameAction(OWNER_2, DEFAULT_KS_1)

        self.tool.addAction(action1)
        self.tool.addAction(action2)

        newKs = {"vk": 90, "modifiers": []}
        setSharedKeyBinding(newKs)

        assertNoLoggedMessages()
        assertKeyBinding(action1, newKs)
        assertKeyBinding(action2, newKs)
        assertSharedStubInTool()

    # ... and so on for the rest of the tests

class FakeDockingTool:
    pass

def setSharedKeyBinding(newKs):
    options = self.tool.getOptions(DockingToolConstants.KEY_BINDINGS)
    runSwing(lambda: options.setKeyStroke(SHARED_NAME, newKs))
    waitForSwing()

def assertNoLoggedMessages():
    self.assertTrue("Spy logger not empty" + str(self.spyLogger), IterableUtils.isEmpty(self.spyLogger))

class SharedNameAction:
    def __init__(self, owner, ks):
        super().__init__(SHARED_NAME, owner, KeyBindingType.SHARED)
        self.setKeyBindingData(ks)

    @unittest.skip("Method is not implemented")
    def actionPerformed(self, context):
        fail("Action performed should not have been called")

class TestNonSharedAction:
    def __init__(self, owner, ks):
        super().__init__(NON_SHARED_NAME, owner, KeyBindingType.INDIVIDUAL)
        self.setKeyBindingData(ks)

    @unittest.skip("Method is not implemented")
    def actionPerformed(self, context):
        fail("Action performed should not have been called")

class DummyComponentProvider:
    def __init__(self):
        super().__init__(tool, "Dummy", "Dummy Owner")
        addToTool()

    def getComponent(self):
        return None

if __name__ == "__main__":
    unittest.main()
