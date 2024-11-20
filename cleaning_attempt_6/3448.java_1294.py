import java.awt.Color as Color
from javax.swing import ImageIcon
from org.apache.commons.lang3.StringUtils import isBlank
from ghidra.app.services import MarkerService
from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.listing import *
from ghidra.util import HTMLUtilities

class BookmarkNavigator:
    BIG_CHANGE = 1000
    
    NOTE_ICON = ResourceManager.load_image("images/notes.gif")
    INFO_ICON = ResourceManager.load_image("images/information.png")
    WARNING_ICON = ResourceManager.load_image("images/warning.png")
    ERROR_ICON = ResourceManager.load_image("images/edit-delete.png")
    ANALYSIS_ICON = ResourceManager.load_image("images/applications-system.png")
    DEFAULT_ICON = ResourceManager.load_image("images/unknown.gif")

    NOTE_PRIORITY = MarkerService.BOOKMARK_PRIORITY
    WARNING_PRIORITY = MarkerService.BOOKMARK_PRIORITY + BIG_CHANGE / 2
    INFO_PRIORITY = MarkerService.BOOKMARK_PRIORITY + 4
    ANALYSIS_PRIORITY = MarkerService.BOOKMARK_PRIORITY + 6
    ERROR_PRIORITY = MarkerService.BOOKMARK_PRIORITY + 8

    NOTE_COLOR = Color(128,0,255)
    WARNING_COLOR = Color(255,196,51)
    INFO_COLOR = Color(0,255,255)
    ANALYSIS_COLOR = Color(255,128,0)
    DEFAULT_COLOR = Color(255,0,255)

    def __init__(self, marker_service: MarkerService, bookmark_manager: BookmarkManager, bmt):
        self.marker_service = marker_service
        self.bookmark_mgr = bookmark_manager
        self.type = bmt.get_type_string()
        
        update_runnable = lambda: self.update_marker_set_addresses()

        priority = bmt.get_marker_priority()
        if priority < 0:
            priority = DEFAULT_PRIORITY

        icon = bmt.get_icon()
        if icon is None:
            icon = DEFAULT_ICON
        
        color = bmt.get_marker_color()
        if color is None:
            color = DEFAULT_COLOR
        
        self.marker_set = marker_service.create_point_marker(self.type + " Bookmarks", 
                                                              self.type + " Bookmarks",
                                                              bookmark_manager.get_program(),
                                                              priority, True, True, False,
                                                              color, icon)

        self.marker_set.set_marker_descriptor(lambda loc: self.tooltip(loc))

    def update_marker_set_addresses(self):
        if self.address_set is not None and self.marker_set is not None:
            self.marker_set.set_address_set(self.address_set)
            self.address_set = None

    def dispose(self):
        if self.marker_service is not None:
            self.marker_service.remove_marker(self.marker_set, 
                                              bookmark_manager.get_program())
            self.marker_set = None
            self.bookmark_mgr = None

    @property
    def type(self):
        return self._type

    def update_bookmarkers(self, address_set: AddressSet):
        if self.address_set is not None:
            self.address_set = address_set
            Swing.run_later(update_runnable)

    def add(self, addr: Address):
        self.marker_set.add(addr)

    def clear(self, addr: Address):
        self.marker_set.clear(addr)

    def intersects(self, start: Address, end: Address) -> bool:
        return self.marker_set.intersects(start, end)

    @staticmethod
    def define_bookmark_types(program: Program):
        bookmark_manager = program.get_bookmark_manager()
        bookmark_manager.define_type(BookmarkType.NOTE, NOTE_ICON, NOTE_COLOR, NOTE_PRIORITY)
        bookmark_manager.define_type(BookmarkType.INFO, INFO_ICON, INFO_COLOR, INFO_PRIORITY)
        bookmark_manager.define_type(BookmarkType.WARNING, WARNING_ICON, WARNING_COLOR, WARNING_PRIORITY)
        bookmark_manager.define_type(BookmarkType.ERROR, ERROR_ICON, ERROR_COLOR, ERROR_PRIORITY)
        bookmark_manager.define_type(BookmarkType.ANALYSIS, ANALYSIS_ICON, ANALYSIS_COLOR, ANALYSIS_PRIORITY)

    def tooltip(self, loc: MarkerLocation) -> str:
        bookmarks = self.bookmark_mgr.get_bookmarks(loc.addr(), self.type)
        if bookmarks is None:
            return self.type
        buffy = StringBuilder()
        for i in range(len(bookmarks)):
            if i != 0:
                buffy.append("<br>")
            buffy.append(self.type)
            cat = bookmarks[i].get_category()
            if not is_blank(cat):
                buffy.append(" [")
                buffy.append(HTMLUtilities.escape_html(cat))
                buffy.append("]")
            buffy.append(": ")
            buffy.append(HTMLUtilities.escape_html(bookmarks[i].get_comment()))
        return buffy.toString()

class BookmarkManager:
    def get_program(self) -> Program:
        pass

    def define_type(self, bmt: BookmarkType):
        pass

    def get_bookmark_types(self) -> list[BookmarkType]:
        pass

    def get_bookmarks(self, addr: Address, type: str) -> list[Bookmark]:
        pass
