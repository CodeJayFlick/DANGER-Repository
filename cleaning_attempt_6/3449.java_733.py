import threading
from typing import List, Set, Dict

class BookmarkPlugin:
    def __init__(self):
        self.provider = None  # type: BookmarkProvider
        self.addAction = None  # type: DockingAction
        self.deleteAction = None  # type: DockingAction
        self.createDialog = None  # type: CreateBookmarkDialog
        self.goToService = None  # type: GoToService
        self.markerService = None  # type: MarkerService
        self.bookmarkMgr = None  # type: BookmarkManager
        self.repaintMgr = None  # type: SwingUpdateManager
        self.navUpdater = NavUpdater()
        self.bookmarkNavigators = {}  # type: Dict[str, BookmarkNavigator]

    def readConfigState(self):
        super().readConfigState()

    def writeConfigState(self):
        if self.provider is not None:
            self.provider.writeConfigState()

    def createActions(self):
        self.addAction = AddBookmarkAction(self)
        self.deleteAction = DeleteBookmarkAction(self)

    def filterBookmarks(self):
        # implementation

    def dispose(self):
        self.navUpdater.dispose()
        self.repaintMgr.dispose()
        if self.addAction is not None:
            self.addAction.dispose()

    def initializeBookmarkers(self):
        # implementation

    def typeAdded(self, type: str):
        self.provider.typeAdded(type)
        getBookmarkNavigator(type)

    def bookmarkChanged(self, bookmark: Bookmark):
        # implementation

    def setNote(self, addr: Address, category: str, comment: str):
        # implementation

    def deleteBookmark(self, bookmark: Bookmark):
        # implementation

    def showAddBookmarkDialog(self, location: Address):
        # implementation

    class NavUpdater(threading.Thread):
        def __init__(self):
            super().__init__()
            self.types = set()
            self.updateMgr = SwingUpdateManager(MIN_ TIMEOUT, MAX_TIMEOUT)
            self.running = False
            self.program = None  # type: Program

        def addType(self, type: str):
            if type is not None:
                self.types.add(type)

        def dispose(self):
            self.updateMgr.dispose()

    class BookmarkNavigator:
        pass

class AddBookmarkAction(DockingAction):
    pass

class DeleteBookmarkAction(DockingAction):
    pass
