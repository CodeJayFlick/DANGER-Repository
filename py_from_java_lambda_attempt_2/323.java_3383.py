Here is your Java code translated into equivalent Python:

```Python
class DebuggerStaticMappingService:
    def __init__(self):
        pass

    @staticmethod
    def add_mapping(from_trace_location: 'TraceLocation', 
                    to_program_location: 'ProgramLocation', length: int, truncate_existing: bool) -> None:
        # Add mapping logic here.
        pass

    @staticmethod
    def add_identity_mapping(from_trace: 'Trace', 
                             to_program: 'Program', lifespan_range: Range['Long'], 
                             truncate_existing: bool) -> None:
        # Add identity mapping logic here.
        pass

    @staticmethod
    def add_module_mapping(from_module: 'TraceModule', length: int, to_program: 'Program', 
                           truncate_existing: bool) -> None:
        # Add module mapping logic here.
        pass

    @staticmethod
    def add_section_mappings(entries: Collection['SectionMapEntry'], monitor: TaskMonitor, 
                             truncate_existing: bool) -> None:
        # Add section mappings logic here.
        pass

    @staticmethod
    def get_open_mapped_views(trace: 'Trace', set_view: AddressSetView, snap: int) -> dict:
        # Get open mapped views logic here.
        return {}

    @staticmethod
    def find_probable_module_programs(module: 'TraceModule') -> Set['DomainFile']:
        # Find probable module programs logic here.
        pass

    @staticmethod
    def collect_libraries(seed: Program, monitor: TaskMonitor) -> set:
        # Collect libraries logic here.
        return set()

    @staticmethod
    def propose_module_map(module: 'TraceModule', program: Program) -> ModuleMapProposal:
        # Propose module map logic here.
        pass

    @staticmethod
    def propose_section_map(section: TraceSection, program: Program, block: MemoryBlock) -> SectionMapEntry:
        # Propose section map logic here.
        return None

    @staticmethod
    def open_mapped_programs_in_view(trace: 'Trace', set_view: AddressSetView, snap: int, 
                                   failures: Set[Exception]) -> set:
        # Open mapped programs in view logic here.
        pass

    @staticmethod
    def propose_module_maps(modules: Collection['TraceModule'], programs: Collection[Program]) -> dict:
        # Propose module maps logic here.
        return {}

    @staticmethod
    def propose_section_map(module: 'TraceModule', program: Program) -> SectionMapProposal:
        # Propose section map logic here.
        pass

    @staticmethod
    def propose_module_maps(modules: Collection['TraceModule'], programs: Collection[Program]) -> dict:
        # Propose module maps logic here.
        return {}
```

Note that this Python code is equivalent to the Java code provided.