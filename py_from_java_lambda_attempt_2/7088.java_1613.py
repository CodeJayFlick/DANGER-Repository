Here is a translation of the Java code into equivalent Python:

```Python
class CDexLoader:
    def __init__(self):
        pass

    def get_name(self):
        return "CDexConstants.NAME"

    def get_tier(self):
        return "UNTARGETED_LOADER"

    def get_tier_priority(self):
        return 100

    def find_supported_load_specs(self, provider) -> list:
        load_specs = []
        
        reader = BinaryReader(provider, True)
        try:
            magic_bytes = provider.read_bytes(0, len(CDexConstants.MAGIC))
            if CDexConstants.MAGIC == bytes(magic_bytes).decode("utf-8"):
                header = DexHeaderFactory.get_dex_header(reader)  # should be CDEX
                if CDexConstants.MAGIC == bytes(header.magic()).decode("utf-8"):
                    queries = QueryOpinionService.query(self.get_name(), "DexConstants. MACHINE", None)
                    for result in queries:
                        load_specs.append(LoadSpec(self, 0, result))
                    if not load_specs:
                        load_specs.append(LoadSpec(self, 0, True))
        except Exception as e:
            # ignore
            pass
        
        return load_specs

    def supports_load_into_program(self):
        return True

    def load(self, provider: bytes, load_spec: str, options: list, program: dict, monitor: object, log: object) -> None:
        try:
            start = Address(program["address_factory"]["default_address_space"], 0)
            length = len(provider)

            with InputStream(provider.get_input_stream(0)) as input_stream:
                program["memory"].create_initialized_block(".cdex", start, input_stream, length, monitor, False)

            reader = BinaryReader(provider, True)
            header = DexHeaderFactory.get_dex_header(reader)

            monitor.set_message("CDEX Loader: creating cdex memory")

            create_method_lookup_memory_block(program, monitor)
            create_method_byte_code_block(program, len(length), monitor)

            for item in header.class_defs():
                if not class_data_item:
                    continue

                create_methods(program, header, item, class_data_item.direct_methods(), monitor, log)
                create_methods(program, header, item, class_data_item.virtual_methods(), monitor, log)
        except Exception as e:
            log.append_exception(e)

    def create_method_byte_code_block(self, program: dict, length: int, monitor: object) -> None:
        address = to_addr(program["address_factory"]["default_address_space"], DexUtil.METHOD_ADDRESS)
        block = program["memory"].create_initialized_block("method_ byte code", address, length, 0xff, monitor, False)
        block.set_read(True)
        block.set_write(False)
        block.set_execute(True)

    def create_method_lookup_memory_block(self, program: dict, monitor: object) -> None:
        address = to_addr(program["address_factory"]["default_address_space"], DexUtil.LOOKUP_ADDRESS)
        block = program["memory"].create_initialized_block("method_ lookup", address, DexUtil.MAX_METHOD_LENGTH, 0xff, monitor, False)
        block.set_read(True)
        block.set_write(False)
        block.set_execute(False)

    def create_methods(self, program: dict, header: object, item: str, methods: list, monitor: object, log: object) -> None:
        for i in range(len(methods)):
            encoded_method = methods[i]
            
            code_item = encoded_method.code_item()
            
            method_index_address = DexUtil.to_lookup_address(program["address_factory"]["default_address_space"], encoded_method.method_index())
            
            if not code_item:
                # external method, ignore
                pass
            else:
                method_address = to_addr(program["address_factory"]["default_address_space"], DexUtil.METHOD_ADDRESS + encoded_method.code_offset())

                instruction_bytes = code_item.instruction_bytes()
                program["memory"].set_bytes(method_address, instruction_bytes)

                program["memory"].set_int(method_index_address, int(method_address.offset()))

    def to_addr(self, address: object, offset: long) -> Address:
        return address.get_address_space().get_address(offset)
```

Please note that this is a translation of the Java code into equivalent Python. It may not be exactly what you want as it might require some adjustments based on your specific requirements and constraints.