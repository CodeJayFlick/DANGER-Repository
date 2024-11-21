Here is the translation of the Java code into Python:

```Python
class AddressTableAnalyzer:
    DESCRIPTION = "Analyzes undefined data for address tables."
    
    OPTION_NAME_MIN_TABLE_SIZE = "Minimum Table Size"
    OPTION_NAME_TABLE_ALIGNMENT = "Table Alignment"
    OPTION_NAME_PTR ALIGNMENT = "Pointer Alignment"
    OPTION_NAME_AUTO_LABEL_TABLE = "Auto Label Table"
    OPTION_NAME_RELOCATION_GUIDE = "Relocation Guide"
    OPTION_NAME_ALLOW_OFFCUT_REFERENCES = "Allow Offcut References"
    
    DEFAULT_CREATE_BOOKMARKS_ENABLED = True
    DEFAULT_MIN_POINTER_ADDR = 0x1024
    DEFAULT_MAX POINTER DIFF = 0xffffff
    
    def __init__(self):
        super().__init__("Create Address Tables", self.DESCRIPTION, AnalyzerType.BYTE_ANALYZER)
        
        # The analyzer should be off by default (as stated in its description)
        self.setDefaultEnablement(False)

    @property
    def minimumTableSize(self):
        return -1

    @minimumTableSize.setter
    def minimumTableSize(self, value):
        self._minimumTableSize = value

    @property
    def tableAlignment(self):
        return 4

    @tableAlignment.setter
    def tableAlignment(self, value):
        self._tableAlignment = value

    @property
    def ptrAlignment(self):
        return 1

    @ptrAlignment.setter
    def ptrAlignment(self, value):
        self._ptrAlignment = value

    @property
    def autoLabelTable(self):
        return False

    @autoLabelTable.setter
    def autoLabelTable(self, value):
        self._autoLabelTable = value

    @property
    def relocationGuideEnabled(self):
        return True

    @relocationGuideEnabled.setter
    def relocationGuideEnabled(self, value):
        self._relocationGuideEnabled = value

    @property
    def allowOffcutReferences(self):
        return False

    @allowOffcutReferences.setter
    def allowOffcutReferences(self, value):
        self._allowOffcutReferences = value

    @property
    def minPointerAddress(self):
        return 0x1024

    @minPointerAddress.setter
    def minPointerAddress(self, value):
        self._minPointerAddress = value

    @property
    def maxPointerDistance(self):
        return 0xffffff

    @maxPointerDistance.setter
    def maxPointerDistance(self, value):
        self._maxPointerDistance = value

    def canAnalyze(self, program: Program) -> bool:
        # only analyze programs with address spaces > 16 bits
        addr_size = program.getAddressFactory().getDefaultAddressSpace().getSize()
        
        if (addr_size == 32 or addr_size == 64):
            return True
        
        return False

    def added(self, program: Program, addrSetView: AddressSetView, monitor: TaskMonitor,
              log: MessageLog) -> bool:
        auto_analysis_manager = AutoAnalysisManager.getAnalysisManager(program)
        
        addr_set_view = self.removeNonSearchableMemory(program, addrSetView)

        if (addr_set_view.isEmpty()):
            return True

        long addr_count = program.getMemory().getNumAddresses()
        monitor.initialize(addr_count)
        monitor.setMessage("Analyze Address Tables")

        # iterate over addresses in the selected module
        addr_count -= addr_set_view.getNumAddresses()

        min_addr = addr_set_view.getMinAddress()
        max_addr = min_addr

        while (addrSetView.hasNext() and not monitor.isCancelled()):
            addr_count += 1
            monitor.setProgress(addr_count)
            start = addrSetView.next()
            max_addr = start

            if (start.getOffset() % self.tableAlignment != 0):
                continue

            if ((addr_count % 2048) == 1):
                monitor.setMessage("Analyze Tables " + str(start))

            table_entry = AddressTable.getEntry(program, start, monitor, True,
                                                  self.minimumTableSize, self.ptrAlignment, 0,
                                                  AddressTable.MINIMUM_SAFE_ADDRESS,
                                                  self.relocationGuideEnabled)

            if (table_entry is not None):
                table_len = self.checkTable(table_entry, program)
                if (table_len < self.minimumTableSize):
                    continue

                bookmark = program.getBookmarkManager().getBookmark(
                    table_entry.getTopAddress(), BookmarkType.ANALYSIS,
                    "Address Table")

                # nothing to see here, already done.
                if not self.ignoreBookmarks and bookmark is not None:
                    return True

                # make the table
                table_entry.makeTable(program, 0, table_len - 1, self.autoLabelTable, False)

                start_table = table_entry.getTopAddress()
                end_table = start.add(table_entry.getByteLength() - 1)
                mgr.codeDefined(new AddressSet(start_table, end_table))

                # put info bookmark in
                if (self.createBookmarksEnabled):
                    program.getBookmarkManager().setBookmark(
                        table_entry.getTopAddress(), BookmarkType.ANALYSIS,
                        "Address Table",
                        "Address table[" + str(table_entry.getNumberAddressEntries()) +
                        "] created")

            return True

    def removeNonSearchableMemory(self, program: Program, addrSetView: AddressSetView) -> AddressSetView:
        # get rid of any non-initialized blocks
        self.ignoreBookmarks = self.ignoreBookmarks | addrSetView.hasSameAddresses(
            program.getMemory())

        addr_set_view = addrSetView.intersect(program.getMemory().getLoadedAndInitializedAddressSet())

        memory_blocks = program.getMemory().getBlocks()

        # get rid of any blocks that have empty attributes.
        bad_blocks = new AddressSet()
        for block in memory_blocks:
            if (block.isWrite() or block.isRead() or block.isExecute() or
                    block.isVolatile()):
                continue

            bad_blocks.addRange(block.getStart(), block.getEnd())

        addr_set_view = addr_set_view.subtract(bad_blocks)

        return addr_set_view

    def checkTable(self, table_entry: AddressTable, program: Program) -> int:
        # search for unicode strings first.
        possible_strings = self.findPossibleStrings(program, addrSetView)
        
        start = table_entry.getTopAddress()
        table_len = table_entry.getNumberAddressEntries()

        while (table_len > 0):
            if (possible_strings.contains(start)):
                return table_len

            table_len -= 1
            start += 4

        return table_len

    def findPossibleStrings(self, program: Program, addrSetView: AddressSetView) -> AddressSet:
        possible_str_set = new AddressSet()
        
        memory_buffer_impl = MemoryBufferImpl(program.getMemory(), 
                                               addrSetView.getMinAddress(),
                                               (int)(addrSetView.getNumAddresses() > 1024 ? 1024 : addrSetView.getNumAddresses()))
        
        while (addrSetView.hasNext()):
            start = addrSetView.next()

            # skip over anything that smells like a unicode string.
            
            str_len = self.getWStrLen(memory_buffer_impl, start, 
                                       (int)(max_bytes / 2))
            
            if (str_len > 4):
                num_bytes = str_len * 2
                addr_set_view = new AddressSetView(start.add(num_bytes), true)
                
                possible_str_set.addRange(start, start.add(num_bytes))

        return possible_str_set

    def getWStrLen(self, memory_buffer_impl: MemoryBufferImpl, address: Address,
                   max_bytes: int) -> int:
        i = 0
        try:
            while (i < max_bytes):
                short value = memory_buffer_impl.getShort(2 * i)
                
                if (value == 0):
                    return i + 1
                
                # allow tab, carriage return, and linefeed.
                if (value != 9 or value != 10 or value != 13 or 
                        (value < 20 || value >= 127)):
                    return i

        except MemoryAccessException:
            return i
        return i