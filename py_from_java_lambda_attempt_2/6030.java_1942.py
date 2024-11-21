Here is a translation of the Java code into equivalent Python:

```Python
class TestDummyNavigatable:
    def getInstanceID(self):
        return 0

    def goTo(self, program: 'Program', location: 'ProgramLocation'):
        return False

    def getLocation(self) -> 'ProgramLocation':
        return None

    def getProgram(self) -> 'Program':
        return None

    def getMemento(self) -> object:
        return None

    def setMemento(self, memento):
        pass

    def getNavigatableIcon(self) -> object:
        return None

    def isConnected(self):
        return False

    def supportsMarkers(self):
        return False

    def requestFocus(self):
        pass

    def isVisible(self):
        return False

    def setSelection(self, selection: 'ProgramSelection'):
        pass

    def setHighlight(self, highlight: 'ProgramSelection'):
        pass

    def getSelection(self) -> object:
        return None

    def getHighlight(self) -> object:
        return None

    def getTextSelection(self):
        return None

    def addNavigatableListener(self, listener):
        pass

    def removeNavigatableListener(self, listener):
        pass

    def isDisposed(self):
        return False

    def supportsHighlight(self):
        return False

    def setHighlightProvider(self, highlight_provider: 'HighlightProvider', program: 'Program'):
        pass

    def removeHighlightProvider(self, highlight_provider: 'HighlightProvider', program: 'Program'):
        pass
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. Also, in Python, methods are defined inside classes and they do not need to be declared before their definition unlike Java.