class EmbeddedMediaAnalyzer:
    NAME = "Embedded Media"
    DESCRIPTION = "Finds embedded media data types (ie png, gif, jpeg, wav)"
    
    OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks"
    OPTION_DESCRIPTION_CREATE_BOOKMARKS = "If checked, an analysis bookmark will be created at each location where embedded media data is identified."
    OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = True
    
    def __init__(self):
        self.create_bookmarks_enabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED
        super().__init__(NAME, DESCRIPTION)

    def added(self, program: 'Program', set: 'AddressSetView', monitor: 'TaskMonitor', log: 'MessageLog'):
        memory = program.get_memory()
        valid_memory_set = memory.get_loaded_and_initialized_address_set()
        search_set = set.intersect(valid_memory_set)
        
        if not search_set:
            return False
        
        searcher = MemoryBytePatternSearcher("Embedded Media")
        
        found_media = []
        
        self.add_byte_search_pattern(searcher, program, found_media, GifDataType(), "GIF 87", 
                                       GifDataType.MAGIC_87, GifDataType.GIFMASK)
        
        self.add_byte_search_pattern(searcher, program, found_media, PngDataType(), "PNG",
                                      PngDataType.MAGIC, PngDataType.MASK)
        
        self.add_byte_search_pattern(searcher, program, found_media, JPEGDataType(), "JPEG", 
                                       JPEGDataType.MAGIC, JPEGDataType.MAGIC_MASK)
        
        self.add_byte_search_pattern(searcher, program, found_media, WAVEDataType(), "WAVE",
                                      WAVEDataType.MAGIC, WAVEDataType.MAGIC_MASK)
        
        self.add_byte_search_pattern(searcher, program, found_media, AUDataType(), "AU", 
                                       AUDataType.MAGIC, AUDataType.MAGIC_MASK)
        
        self.add_byte_search_pattern(searcher, program, found_media, AIFFDataType(), "AIFF",
                                      AIFFDataType.MAGIC, AIFFDataType.MAGIC_MASK)
        
        searcher.search(program, search_set, monitor)
        
        return len(found_media) > 0

    def add_byte_search_pattern(self, searcher: 'MemoryBytePatternSearcher', program: 'Program',
                                 found_media: list, media_dt: 'DataType', name: str,
                                 bytes: bytearray, mask: bytearray):
        if not bytes:
            return
        
        action = GenericMatchAction(media_dt)
        
        try:
            cmd = CreateDataCmd(program.get_address(), media_dt)
            if cmd.apply_to(program):
                if self.create_bookmarks_enabled:
                    program.get_bookmark_manager().set_bookmark(
                        program.get_address(),
                        BookmarkType.ANALYSIS,
                        "Embedded Media",
                        f"Found {name} Embedded Media"
                    )
                found_media.append(program.get_address())
        except Exception as e:
            pass

    def register_options(self, options: 'Options', program: 'Program'):
        options.register_option(OPTION_NAME_CREATE_BOOKMARKS, self.create_bookmarks_enabled,
                                 None, OPTION_DESCRIPTION_CREATE_BOOKMARKS)

    def options_changed(self, options: 'Options', program: 'Program'):
        self.create_bookmarks_enabled = options.get_boolean(
            OPTION_NAME_CREATE_BOOKMARKS, self.create_bookmarks_enabled
        )
