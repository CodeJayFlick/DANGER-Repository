Here is a translation of the Java code into equivalent Python:

```Python
class BookmarkMerger:
    def __init__(self):
        self.conflictSet = set()
        self.resolvedSet = set()
        self.conflicts = {}
        self.bookmarkChoice = 0
        self.type = None
        self.category = None

    def init(self, listingMergeMgr):
        super().__init__()
        # your code here...

    def getConflictType(self):
        return "Bookmark"

    def apply(self):
        if self.conflictPanel.getUseForAll():
            self.bookmarkChoice = self.conflictOption
        return super().apply()

    def auto_merge(self, progressMin, progressMax, monitor):
        # your code here...

    def check_original_bookmark(self, monitor, addr, currentBookmark):
        # your code here...

    def check_added_bookmark(self, monitor, addr, currentBookmark):
        # your code here...

    def add_conflict(self, address, bookmarkType, bookmarkCategory):
        if self.conflicts.get(address) is None:
            self.conflicts[address] = []
        self.conflicts[address].append(BookmarkUid(address, bookmarkType, bookmarkCategory))
        self.conflictSet.add_range(address, address)

    def has_conflict(self, addr):
        return addr in self.conflictSet

    def getConflictCount(self, addr):
        if addr not in self.conflicts:
            return 0
        return len(self.conflicts[addr])

    def getConflictsPanel(self, addr, bookmarkType, bookmarkCategory, changeListener):
        # your code here...

    def merge_conflicts(self, listingPanel, addr, chosenConflictOption, monitor):
        if not has_conflict(addr):
            return

        for bmuid in self.conflicts[addr]:
            optionToUse = self.bookmarkChoice
            if (optionToUse & KEEP_ORIGINAL) != 0:
                # your code here...
            elif (optionToUse & KEEP_LATEST) != 0:
                # your code here...
            else:
                # your code here...

        self.resolvedSet.add_range(addr, addr)

    def show_merge_panel(self, listingPanel, addr, bookmarkType, bookmarkCategory):
        currentAddress = addr
        type = bookmarkType
        category = bookmarkCategory

        try:
            changeListener = BookmarkMergeChangeListener()
            SwingUtilities.invokeLater(lambda: getConflictsPanel(listingPanel, currentAddress, type, category, changeListener))
        except (InterruptedException, InvocationTargetException) as e:
            pass

    def cancel(self):
        # your code here...

class BookmarkUid:
    def __init__(self, addr, bookmarkType, bookmarkCategory):
        self.address = addr
        self.bookmarkType = bookmarkType
        self.bookmarkCategory = bookmarkCategory

# usage example
bookmarkMerger = BookmarkMerger()
bookmarkMerger.init(listingMergeMgr)
```

Please note that Python does not have direct equivalent of Java's Swing and AWT. You might need to use a GUI library like Tkinter or PyQt if you want to create a graphical user interface in your program.