Here is a translation of the Java code into Python:

```Python
class SearchTextPlugin:
    def __init__(self):
        self.searchDialog = None
        self.navigatable = None
        self.currentTask = None
        self.waitingForSearchAll = False
        self.lastSearchedText = ""
        self.highlightColor = None
        self.currentAddrHighlightColor = None
        self.doHighlight = True

    def setNavigatable(self, navigatable):
        if self.navigatable != navigatable:
            if self.navigatable is not None:
                self.navigatable.removeNavigatableListener(self)
            self.navigatable = navigatable
            if self.searchDialog is not None and self.searchDialog.isVisible():
                self.searchDialog.setSearchEnabled(navigatable is not None)

    def updateSelection(self, context):
        if self.searchDialog is not None:
            self.searchDialog.setHasSelection(context.hasSelection())

    def displayDialog(self, context):
        if self.searchDialog is None:
            self.searchDialog = SearchTextDialog(self)
            self.searchDialog.setHasSelection(context.hasSelection())
        text_selection = self.navigatable.get_text_selection()
        location = self.navigatable.getLocation()
        address = location.getAddress()
        listing = context.getProgram().getListing()
        code_unit = listing.getCodeUnitAt(address)
        is_instruction = False
        if text_selection is not None:
            if code_unit is not None:
                if isinstance(code_unit, Instruction):
                    is_instruction = True
                else:
                    is_instruction = False
            self.searchDialog.setCurrentField(location, is_instruction)

    def searchAll(self, options):
        program_selection = self.navigatable.getSelection()
        program = self.navigatable.getProgram()
        address_set_view = getMemoryAddressSet(program, options)
        if program_selection is not None and not program_selection.isEmpty() and self.searchDialog.searchSelection():
            address_set_view = address_set_view.intersect(program_selection)

    def getAddressSet(self, navigatable, options):
        memory = navigatable.getProgram().getMemory()
        if options.includeNonLoadedMemoryBlocks():
            return memory
        address_set = AddressSet()
        for block in memory.getBlocks():
            if block.isLoaded():
                start_address = block.getStart()
                end_address = block.getEnd() - 1
                address_set.add(start_address, end_address)
        return address_set

    def getHighlights(self):
        match_str = self.searchOptions.getText().trim()
        if match_str is None or text is None:
            return []
        list_ = []
        pattern = UserSearchUtils.create_search_pattern(match_str, self.searchOptions.isCaseSensitive())
        matcher = pattern.match(text)
        while matcher.find():
            start_index = matcher.start()
            end_index = matcher.end() - 1
            if start_index <= cursor_text_offset and end_index >= cursor_text_offset:
                list_.append(Highlight(start_index, end_index, self.current_addr_highlight_color))
            elif loc is None:  # only add in matches around current match if loc is null
                # meaning that this is a one at a time search and not a table of results.
                list_.append(Highlight(start_index, end_index, highlight_color))

        return [Highlight(*highlight) for highlight in list_]

    def should_highlight(self):
        program = self.navigatable.getProgram()
        if program != self.highlight_program:
            return False
        if self.search_options.search_all_fields():
            return True
        if self.search_options.search_comments() and (factory_class == PreCommentFieldFactory.class or factory_class == PlateFieldFactory.class or factory_class == PostCommentFieldFactory.class or factory_class == EolCommentFieldFactory.class):
            return True

    def check_remove_highlights(self):
        if provider is not None:  # search all - remove highlights when results are no longer showing
            if self.search_dialog.is_visible(provider) and tool.get_options().get_boolean_value("search_all_fields"):
                highlight_navigatable.remove_highlight_provider(self, highlight_program)
                return True

    def getMemoryAddressSet(self):
        memory = navigatable.getProgram().getMemory()
        address_set_view = memory
        if self.searchOptions.isCaseSensitive():
            return AddressSet()

class SearchTextDialog:
    pass