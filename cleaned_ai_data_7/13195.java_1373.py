import io
from abc import ABCMeta, abstractmethod
class AbstractLibrarySupportLoader(metaclass=ABCMeta):
    @abstractmethod
    def find_supported_load_specs(self, byte_provider) -> list:
        pass

    @abstractmethod
    def load(self, byte_provider: bytes, program: object, task_monitor: object,
             message_log: object = None) -> None:
        pass


class JavaLoader(AbstractLibrarySupportLoader):
    JAVA_NAME = "Java Class File"
    CODE_OFFSET = 0x10000L
    CONSTANT_POOL = "constantPool"

    def find_supported_load_specs(self, byte_provider: bytes) -> list:
        load_specs = []
        valid_class = False

        if self.check_class(byte_provider):
            valid_class = True

        if valid_class:
            load_specs.append(LoadSpec(self, 0,
                                         LanguageCompilerSpecPair("JVM:BE:32:default", "default"), True))

        return load_specs

    def check_class(self, byte_provider: bytes) -> bool:
        reader = BinaryReader(byte_provider, False)
        magic = reader.peek_next_int()
        if magic != JavaClassConstants.MAGIC:
            return False
        try:
            ClassFileJava(reader)
        except (IOException, RuntimeError):
            return False

        return True

    def get_name(self) -> str:
        return self.JAVA_NAME

    def load(self, byte_provider: bytes, program: object, task_monitor: object,
             message_log: object = None) -> None:
        try:
            self.do_load(byte_provider, program, task_monitor)
        except (LockException, MemoryConflictException, AddressOverflowException,
                CancelledException, DuplicateNameException):
            pass

    def do_load(self, byte_provider: bytes, program: object, task_monitor: object) -> None:
        address_factory = program.get_address_factory()
        space = address_factory.get_address_space(self.CONSTANT_POOL)
        memory = program.get_memory()
        self.alignment_reg = program.get_register("alignmentPad")

        reader = BinaryReader(byte_provider, False)
        class_file = ClassFileJava(reader)

        start = space.get_address(0)

        # Create a block of memory with just the right size
        memory.create_initialized_block("_" + byte_provider.name() + "_", start,
                                          io.BytesIO(byte_provider), len(byte_provider),
                                          task_monitor, False)

        self.create_method_lookup_memory_block(program, task_monitor)
        self.create_method_memory_blocks(program, byte_provider, class_file, task_monitor)

    def create_method_lookup_memory_block(self, program: object, task_monitor: object) -> None:
        address = self.to_addr(program, JavaClassUtil.LOOKUP_ADDRESS)
        block = memory.create_initialized_block("method_lookup", address,
                                                 io.BytesIO(b'\xff' * 0x100), len(byte_provider),
                                                 task_monitor, False)

    def create_method_memory_blocks(self, program: object, byte_provider: bytes,
                                    class_file: ClassFileJava, task_monitor: object) -> None:
        constant_pool = class_file.get_constant_pool()
        methods = class_file.get_methods()

        task_monitor.set_message("Processing Methods...")
        task_monitor.set_progress(0)
        task_monitor.set_maximum(len(methods))

        start = self.to_addr(program, self.CODE_OFFSET)

        for i in range(len(methods)):
            method = methods[i]
            code = method.get_code_attribute()
            if code is None:
                continue

            length = code.get_code_length()
            offset = code.get_code_offset()

            memory = program.get_memory()
            name_index = method.get_name_index()
            descriptor_index = method.get_descriptor_index()
            method_name_info = constant_pool[name_index]
            method_descriptor_info = constant_pool[descriptor_index]

            start_address = self.to_addr(program, 0)
            end_address = start.add(length + 1)

            while end_address.get_offset() % 4 != 0:
                end_address = end_address.add(1)

    def to_addr(self, program: object, offset: int) -> Address:
        return program.get_address_factory().get_default_address_space().get_address(offset)
