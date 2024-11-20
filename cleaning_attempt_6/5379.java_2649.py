class DbgLoader:
    MIN_BYTE_LENGTH = 46
    DBG_NAME = "Debug Symbols (DBG)"

    def __init__(self):
        pass

    def find_supported_load_specs(self, provider: bytes) -> list:
        load_specs = []
        if len(provider) < self.MIN_BYTE_LENGTH:
            return load_specs
        
        debug_header = SeparateDebugHeader(RethrowContinuesFactory(), provider)
        
        if debug_header.get_signature() == SeparateDebugHeader.IMAGE_SEPARATE_DEBUG_SIGNATURE:
            image_base = int(debug_header.get_image_base())
            machine_name = debug_header.get_machine_name()
            
            for result in QueryOpinionService().query(self.name, machine_name):
                load_specs.append(LoadSpec(self, image_base, result))
                
            if not load_specs:
                load_specs.append(LoadSpec(self, image_base, True))
        
        return load_specs

    def load(self, provider: bytes, load_spec: LoadSpec, options: list, prog: Program, 
             monitor: TaskMonitor, log: MessageLog):
        factory = MessageLogContinuesFactory(log)
        
        if not isinstance(prog.executable_format(), PeLoader):
            raise IOException("Loading of DBG file may only be 'added' to existing PE Program")
        
        debug_header = SeparateDebugHeader(factory, provider)

        parent_path = prog.executable_path()
        parent_file = File(parent_path)

        try:
            provider2 = RandomAccessByteProvider(parent_file)
            
            pe = PortableExecutable.factory().create_portable_executable(provider2, SectionLayout.FILE)
            image_base = prog.image_base
            section_to_address = {}
            
            file_header = pe.get_nt_header().get_file_header()
            section_headers = file_header.get_section_headers()
            
            for section_header in section_headers:
                section_to_address[section_header] = image_base + int(section_header.virtual_address())
            
            self.process_debug(debug_header.parser(), file_header, section_to_address, prog, monitor)
        finally:
            if provider2 is not None:
                provider2.close()

    def get_name(self):
        return self.DBG_NAME

    def supports_load_into_program(self) -> bool:
        return True


class LoadSpec:
    def __init__(self, loader: DbgLoader, image_base: int, result: any):
        self.loader = loader
        self.image_base = image_base
        self.result = result


class Program:
    pass

class TaskMonitor:
    pass

class MessageLog:
    pass

class PeLoader:
    PE_NAME = "PE"

class SeparateDebugHeader:
    IMAGE_SEPARATE_DEBUG_SIGNATURE = 0x20b

    def __init__(self, factory: any, provider: bytes):
        self.factory = factory
        self.provider = provider

    def get_signature(self) -> int:
        return self.IMAGE_SEPARATE_DEBUG_SIGNATURE

    def get_image_base(self) -> int:
        pass

    def get_machine_name(self) -> str:
        pass


class QueryOpinionService:
    @staticmethod
    def query(name: any, machine_name: str):
        # TO DO: implement the actual logic for this method
        return []
