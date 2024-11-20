Here is your Java code translated into pure Python:

```Python
import unittest
from ghidra.app.service import ProgramManager
from ghidra.program.model.address import Address
from ghidra.framework.plugintool import PluginTool
from ghidra.util.exception import CorruptHostDataException, CorruptObjectException

class ClearTest(unittest.TestCase):
    def setUp(self):
        self.env = None
        self.tool = None
        self.addrFactory = None
        self.program = None
        self.cb = None
        self.clearAction = None
        self.clearWithOptionsAction = None

    def testClearActionEnablement(self):
        closeProgram()
        assertTrue(not clearAction.isEnabledForContext(ActionContext()))

    # ... (rest of the tests)

if __name__ == '__main__':
    unittest.main()

class ClearDialog:
    pass

def okOnClearDialog():
    cd = waitForDialogComponent(ClearDialog)
    runSwing(lambda: cd.okCallback())

def doClearAction(wait):
    actionContext = cb.getProvider().getActionContext(None)
    performAction(clearAction, actionContext, wait)

def adjustFieldPanelSize(numRows):
    fp = cb.getFieldPanel()
    vp = (JViewport) fp.getParent().getParent()
    cb.updateNow()
    rowHeight = getRowSize(fp)
    desiredViewportHeight = rowHeight * numRows
    if d.height != desiredViewportHeight:
        runSwing(lambda: {
            f = tool.getToolFrame();
            d2 = f.getSize();
            d2.height += desiredViewportHeight - d.height;
            f.setSize(d2);
            fp.invalidate();
            f.validate()
        })
    cb.updateNow()

def getRowSize(fp):
    rowHeight = 0
    layoutModel = fp.getLayoutModel()
    layout = layoutModel.getLayout(BigInteger.ZERO)
    for i in range(layout.getNumFields()):
        field = layout.getField(i)
        numRows = field.getNumRows()
        fieldRowHeight = field.getHeight() / numrows
        return max(rowHeight, fieldRowHeight)

def closeProgram():
    pass

# ... (rest of the functions)

if __name__ == '__main__':
    unittest.main()

class ClearPluginTool:
    pass