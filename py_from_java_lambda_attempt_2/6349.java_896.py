Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin import *
from ghidra.program.model.address import *
from ghidra.framework.options import Options
from ghidra.framework.plugintool import PluginEvent, PluginTool
from ghidra.program.model.mem.memoryblock import MemoryBlock

class DisassembledViewPluginTest(unittest.TestCase):

    def setUp(self):
        self.componentProvider = None
        self.env = TestEnv()
        self.tool = env.getTool()

        tool.addPlugin(CodeBrowserPlugin.class.getName())
        tool.addPlugin(DisassembledViewPlugin.class.getName())

        plugin = env.getPlugin(DisassembledViewPlugin)
        componentProvider = (ComponentProvider) getInstanceField("displayComponent", plugin)

    def tearDown(self):
        if program != None:
            env.release(program)
        env.dispose()
        env = None

    @unittest.skip
    def testProcessingOnLocationChanged(self):

        openProgram("notepad")

        list = (JList) getInstanceField("contentList", componentProvider)

        assertEquals("The component provider has data when it is not visible.", 0, 
            list.getModel().getSize())

        tool.showComponentProvider(componentProvider, True)
        waitForPostedSwingRunnables()

        modelOne = list.getModel()
        
        # now the list should have data, as it will populate itself off of the
        # current program location of the plugin

        assertTrue("The component provider does not have data when it  " + 
            "should.", (modelOne.getSize() != 0))

        CodeBrowserPlugin cbPlugin = getPlugin(tool, CodeBrowserPlugin)
        
        pageDown(cbPlugin.getFieldPanel())
        simulateButtonPress(cbPlugin)
        waitForPostedSwingRunnables()

        modelTwo = list.getModel()
        
        sameData = compareListData(modelOne, modelTwo)

        assertTrue("The contents of the two lists are the same when they  " + 
            "should not be.", !sameData)

    @unittest.skip
    def testProcessingOnSelectionChanged(self):

        openProgram("notepad")

        tool.showComponentProvider(componentProvider, True)
        waitForPostedSwingRunnables()

        list = (JList) getInstanceField("contentList", componentProvider)
        modelContents = list.getModel()
        
        # make sure that nothing happens on a single-selection     
        plugin.processEvent(createProgramSelectionEvent(False))

        assertTrue("The list is not the same after processing a  " + 
            "single-selection event.", compareListData(modelContents, list.getModel()))

        # make sure that the component display is cleared when there is a 
        # multiple-selection
        plugin.processEvent(createProgramSelectionEvent(True))
        
        assertTrue( "The list content did not change after processing a  " + 
            "multiple-selection event.", !compareListData(modelContents, list.getModel()))

    @unittest.skip
    def testDisplayConfiguration(self):

        openProgram("notepad")

        tool.showComponentProvider(componentProvider, True)
        waitForPostedSwingRunnables()

        fieldNames = ["selectedAddressColor", "addressForegroundColor", 
            "backgroundColor", "font"]

        optionsMap = {}

        for fieldName in fieldNames:
            optionsMap[fieldName] = getInstanceField(fieldName, componentProvider)

        # change the global options for the plugin's display options
        opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS)
        
        optionToChange = GhidraOptions.OPTION_SELECTION_COLOR
        currentColor = 
            opt.getColor(optionToChange, (Color) optionsMap["selectedAddressColor"])
        opt.setColor(optionToChange, deriveNewColor(currentColor))

        # the rest of the options to change are stored under a different
        # options node
        opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY)
        
        optionToChange = getInstanceField("ADDRESS_COLOR_OPTION", componentProvider)
        currentColor = 
            opt.getColor(optionToChange, (Color) optionsMap["addressForegroundColor"])
        opt.setColor(optionToChange, deriveNewColor(currentColor))

        optionToChange = getInstanceField("BACKGROUND_COLOR_OPTION", componentProvider)
        currentColor = 
            opt.getColor(optionToChange, (Color) optionsMap["backgroundColor"])
        opt.setColor(optionToChange, deriveNewColor(currentColor))

        optionToChange = getInstanceField("ADDRESS_FONT_OPTION", componentProvider)
        currentFont = 
            opt.getFont(optionToChange, (Font) optionsMap["font"])
        opt.setFont(optionToChange, currentFont.deriveFont((float) currentFont.getSize() + 1))

        # now make sure that the changes have been propogated
        for i in range(len(fieldNames)):
            
            newValue = getInstanceField(fieldNames[i], componentProvider)

            assertTrue("The old value has not changed in response to " + 
                "changing the options. Value: " + fieldNames[i],
                !(newValue.equals(optionsMap[fieldNames[i]])))

    def createProgramSelectionEvent(self, multiSelection):
        programLoc = plugin.getProgramLocation()
        currentAddress = programLoc.getAddress()

        if multiSelection:
            nextAddress = currentAddress.next()
        else:
            nextAddress = currentAddress

        selection = ProgramSelection(currentAddress, nextAddress)
        return PluginEvent("CodeBrowserPlugin", selection, program)

    def deriveNewColor(self, originalColor):
        newColor = None
        
        if originalColor == Color.BLACK:
            newColor = originalColor.brighter()
        else:
            newColor = originalColor.darker()

        return newColor

    def simulateButtonPress(self, cbp):
        runSwing(lambda: click(cbp, 1))

    def pageDown(self, fieldPanel):
        runSwing(lambda: fieldPanel.pageDown())

    def compareListData(self, modelOne, modelTwo):
        isSame = False
        
        if modelOne.getSize() == modelTwo.getSize():
            isSame = True
            
            for i in range(modelOne.getSize()):
                if modelOne.getElementAt(i) == None:
                    isSame = (modelTwo.getElementAt(i) == None)
                else:
                    isSame = (modelOne.getElementAt(i).equals(modelTwo.getElementAt(i)))
        
        return isSame

    def openProgram(self, name):
        builder = ClassicSampleX86ProgramBuilder()
        program = builder.getProgram()

        env.showTool(program)
        waitForPostedSwingRunnables()