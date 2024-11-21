Here is the translation of the Java code into Python:

```Python
class DyldCacheLoader:
    DYLD_CACHE_NAME = "DYLD Cache"
    PROCESS_SYMBOLS_OPTION_NAME = "Process symbols"
    CREATE_DYLIB_SECTIONS_OPTION_NAME = "Create DYLIB section memory blocks"
    ADD_RELOCATION_ENTRIES_OPTION_NAME = "Add relocation entries for fixed chain pointers"

    def __init__(self):
        pass

    def find_supported_load_specs(self, provider) -> list:
        load_specs = []
        
        if not DyldCacheUtils.is_dyld_cache(provider):
            return load_specs
        
        try:
            header = DyldCacheHeader(BinaryReader(provider, True))
            architecture = header.get_architecture()
            
            if architecture is not None:
                results = QueryOpinionService.query(self.name(), architecture.processor(), None)
                
                for result in results:
                    load_specs.append(LoadSpec(self, header.base_address(), result))
                    
                if len(load_specs) == 0:
                    load_specs.append(LoadSpec(self, header.base_address(), True))
        except Exception as e:
            pass
        
        return load_specs

    def load(self, provider: bytes, load_spec: LoadSpec, options: list, program: Program, monitor: TaskMonitor, log: MessageLog) -> None:
        try:
            DyldCacheProgramBuilder.build_program(program, provider, MemoryBlockUtils.create_file_bytes(program, provider, monitor), 
                                                  self.should_process_symbols(options), self.should_create_dylib_sections(options), 
                                                  self.should_add_relocation_entries(options), log, monitor)
        except CancelledException as e:
            return
        except Exception as e:
            raise IOException(e.message, e)

    def get_default_options(self, provider: bytes, load_spec: LoadSpec, domain_object: DomainObject, load_into_program: bool) -> list:
        options = super().get_default_options(provider, load_spec, domain_object, load_into_program)
        
        if not load_into_program:
            options.append(Option(PROCESS_SYMBOLS_OPTION_NAME, PROCESS_SYMBOLS_OPTION_DEFAULT))
            options.append(Option(CREATE_DYLIB_SECTIONS_OPTION_NAME, CREATE_DYLIB_SECTIONS_OPTION_DEFAULT))
            options.append(Option(ADD_RELOCATION_ENTRIES_OPTION_NAME, ADD_RELOCATION_ENTRIES_OPTION_DEFAULT))

        return options

    def should_process_symbols(self, options: list) -> bool:
        return OptionUtils.get_option(PROCESS_SYMBOLS_OPTION_NAME, options, PROCESS_SYMBOLS_OPTION_DEFAULT)

    def should_create_dylib_sections(self, options: list) -> bool:
        return OptionUtils.get_option(CREATE_DYLIB_SECTIONS_OPTION_NAME, options, CREATE_DYLIB_SECTIONS_OPTION_DEFAULT)

    def should_add_relocation_entries(self, options: list) -> bool:
        return OptionUtils.get_option(ADD_RELOCATION_ENTRIES_OPTION_NAME, options, ADD_RELOCATION_ENTRIES_OPTION_DEFAULT)

    def get_name(self):
        return self.DYLD_CACHE_NAME
```

Note that this is a direct translation of the Java code into Python. Some minor adjustments were made to conform with Python's syntax and conventions.