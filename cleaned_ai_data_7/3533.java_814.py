class ColorizingServiceProvider:
    DEFAULT_COLOR = (0x84AFD3,)
    COLOR_CHOOSER_TITLE = "Please Select Background Color"

    def __init__(self):
        self.tool = None
        self.colorChooser = None
        self.savedColorHistory = []

    def setProgram(self, program):
        self.program = program

    def getMostRecentColor(self):
        recentColors = self.getRecentColors()
        if recentColors and len(recentColors) > 0:
            return recentColors[0]
        else:
            return DEFAULT_COLOR

    def getRecentColors(self):
        if self.colorChooser is not None:
            colorHistory = self.colorChooser.getColorHistory()
            if colorHistory and len(colorHistory) > 0:
                return colorHistory
        if self.savedColorHistory == []:
            return []
        return self.savedColorHistory

    def setColorHistory(self, colorHistory):
        self.savedColorHistory = colorHistory

    def getColorHistory(self):
        if self.colorChooser is None:
            return []  # nothing has changed
        return self.colorChooser.getColorHistory()

    def getColorFromUser(self, suggested_color=None):
        if self.colorChooser is None:
            self.colorChooser = GhidraColorChooser(Color.WHITE if suggested_color is None else suggested_color)
            self.colorChooser.setTitle(COLOR_CHOOSER_TITLE)
            if len(self.savedColorHistory) > 0:
                self.colorChooser.setColorHistory(self.savedColorHistory)
        chosen_color = self.colorChooser.showDialog(None)
        maybeNotifyConfigChanged(suggested_color, chosen_color)
        return chosen_color

    def maybeNotifyConfigChanged(self, original_color=None, chosen_color=None):
        if chosen_color is None:  # user cancelled
            return
        if original_color and original_color == chosen_color:
            return
        self.tool.setConfigChanged(True)

    def setBackgroundColor(self, min_address, max_address, color):
        map = getColorRangeMap(True)
        if map is not None:
            map.setValue(min_address, max_address, color.getRGB())

    def setBackgroundColor(self, set_view, color):
        map = getColorRangeMap(True)
        if map is not None:
            map.setValue(set_view, color.getRGB())

    def getBackgroundColor(self, address):
        map = getColorRangeMap(False)
        if map is not None:
            value = map.getValue(address)
            if value is not None:
                return Color(*value[:3], True)  # Assuming RGB values
        return None

    def getAllBackgroundColorAddresses(self):
        map = getColorRangeMap(False)
        if map is not None:
            return map.getAddressSet()
        else:
            return AddressSet()

    def getBackgroundColorAddresses(self, color):
        map = getColorRangeMap(False)
        if map is not None:
            return map.getAddressSet(color.getRGB())
        else:
            return AddressSet()

    def clearAllBackgroundColors(self):
        map = getColorRangeMap(False)
        if map is not None:
            map.clearAll()

    def clearBackgroundColor(self, min_address, max_address):
        map = getColorRangeMap(False)
        if map is not None:
            map.clearValue(min_address, max_address)

    def clearBackgroundColor(self, set_view):
        map = getColorRangeMap(False)
        if map is not None:
            map.clearValue(set_view)

    def getColorRangeMap(self, create=False):
        if self.program is None:
            return None
        map = self.program.getIntRangeMap("COLOR_PROPERTY_NAME")
        if map is None and create:
            try:
                map = self.program.createIntRangeMap("COLOR_PROPERTY_NAME")
            except DuplicateNameException as e:  # Assuming this exception type exists in Python
                pass
        return map

class GhidraColorChooser:
    def getColorHistory(self):
        raise NotImplementedError()

    def setColorHistory(self, color_history):
        raise NotImplementedError()

    def showDialog(self, parent=None):
        raise NotImplementedError()
