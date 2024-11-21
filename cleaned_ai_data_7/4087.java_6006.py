import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import ImageTk, Image

class NextPreviousBookmarkAction:
    def __init__(self):
        self.is_forward = True
        self.tool = None

    @property
    def bookmark_icon(self):
        return ImageTk.PhotoImage(Image.open("images/B.gif"))

    @property
    def bookmark_analysis_icon(self):
        return ImageTk.PhotoImage(Image.open("images/applications-system.png"))

    @property
    def bookmark_error_icon(self):
        return ImageTk.PhotoImage(Image.open("images/edit-delete.png"))

    @property
    def bookmark_info_icon(self):
        return ImageTk.PhotoImage(Image.open("images/information.png"))

    @property
    def bookmark_note_icon(self):
        return ImageTk.PhotoImage(Image.open("images/notes.gif"))

    @property
    def bookmark_warning_icon(self):
        return ImageTk.PhotoImage(Image.open("images/warning.png"))

    @property
    def bookmark_unknown_icon(self):
        return ImageTk.PhotoImage(Image.open("images/unknown.gif"))

    def set_tool(self, tool):
        self.tool = tool

    def get_next_address(self, program, address, bookmark_type):
        start = self.get_next_address_to_begin_searching_forward(program, address)
        next_bookmark = self.get_next_bookmark(program, start, True, bookmark_type)
        return next_bookmark.address if next_bookmark else None

    def get_previous_address(self, program, address, bookmark_type):
        start = self.get_next_address_to_begin_searching_backward(program, address)
        next_bookmark = self.get_next_bookmark(program, start, False, bookmark_type)
        return next_bookmark.address if next_bookmark else None

    def get_next_address_to_begin_searching_forward(self, program, address):
        cu = self.get_most_primitive_code_unit_containing(program, address)
        return cu.max_address.next() if cu else address

    def get_next_address_to_begin_searching_backward(self, program, address):
        cu = self.get_most_primitive_code_unit_containing(program, address)
        return cu.min_address.previous() if cu else address

    def get_most_primitive_code_unit_containing(self, program, address):
        cu = program.listing.code_unit_containing(address)
        if not cu:
            return None
        if isinstance(cu, Data):
            data = cu
            cu = data.primitive_at(int(address.subtract(data.address)))
        return cu

    def get_next_bookmark(self, program, address, forward, bookmark_type):
        bookmark_manager = program.bookmark_manager
        iterator = bookmark_manager.get_bookmarks_iterator(address, forward)
        while iterator.has_next():
            next_bookmark = iterator.next()
            if not next_bookmark.address.is_external_address:
                return next_bookmark

    def is_not_built_in_type(self, address, next_bookmark):
        return (next_bookmark.type_string != BookmarkType.ANALYSIS and
               next_bookmark.type_string != BookmarkType.INFO and
               next_bookmark.type_string != BookmarkType.NOTE and
               next_bookmark.type_string != BookmarkType.WARNING and
               next_bookmark.type_string != BookmarkType.ERROR)

    def goto_address(self, service, navigatable, address):
        if not address:
            self.tool.status_info = "Unable to locate another bookmark past the current range in the current direction."
            return

        self.tool.clear_status_info()
        if service and isinstance(service, GoToService):
            navigatable.goto(address)

    def goto_next_previous(self, context, bookmark_type):
        address = self.is_forward.get_next_address(context.program, context.address, bookmark_type) or \
                  self.get_previous_address(context.program, context.address, bookmark_type)
        if not address:
            return

        tk.after(0, lambda: self.goto_address(service=context.tool.service(GoToService), navigatable=context.navigatable(), address=address))

    def set_direction(self, is_forward):
        self.is_forward = is_forward
        self.description = f"Go To {'Next' if is_forward else 'Previous'} Bookmark: {self.get_current_state().name}"
