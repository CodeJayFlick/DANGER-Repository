Here is the translation of the Java code into Python:

```Python
class SymbolServerInstanceCreatorRegistry:
    instance = None

    def __init__(self):
        self.symbol_server_instance_creators_by_priority = {}
        self.register_default_symbol_server_instance_creators()

    @classmethod
    def get_instance(cls):
        if cls.instance is None:
            cls.instance = SymbolServerInstanceCreatorRegistry()
        return cls.instance

    def register_symbol_server_instance_creator(self, priority, location_string_matcher,
                                                   symbol_server_instance_creator):
        symbol_server_instance_creator_info = {
            'location_string_matcher': location_string_matcher,
            'symbol_server_instance_creator': symbol_server_instance_creator
        }
        self.symbol_server_instance_creators_by_priority[priority] = symbol_server_instance_creator_info

    def create_symbol_servers_from_path_list(self, location_strings, context):
        result = []
        for location_string in location_strings:
            symbol_server = self.new_symbol_server(location_string, context)
            if symbol_server is not None:
                result.append(symbol_server)
        return result

    def new_symbol_server(self, symbol_server_location_string, context):
        for priority, info in sorted(self.symbol_server_instance_creators_by_priority.items()):
            if info['location_string_matcher'].test(symbol_server_location_string):
                symbol_server = info['symbol_server_instance_creator'](symbol_server_location_string, context)
                if symbol_server is None:
                    return None
                return symbol_server

        Msg.debug("Symbol server location [{}] not valid, skipping.".format(symbol_server_location_string))
        return None

    def get_context(self):
        return SymbolServerInstanceCreatorContext(self)

    def get_context_with_program(self, program):
        exe_location = FilenameUtils.getFullPath(program.executable_path)
        return SymbolServerInstanceCreatorContext(exe_location, self)


class SymbolServerInstanceCreatorInfo:
    def __init__(self, location_string_matcher, symbol_server_instance_creator):
        self.location_string_matcher = location_string_matcher
        self.symbol_server_instance_creator = symbol_server_instance_creator


def register_default_symbol_server_instance_creators(self):
    self.register_symbol_server_instance_creator(0,
                                                   lambda x: DisabledSymbolServer.is_disabled_symbol_server_location(x),
                                                   lambda loc, context: DisabledSymbolServer.create_instance())

    self.register_symbol_server_instance_creator(100,
                                                   lambda x: HttpSymbolServer.is_http_symbol_server_location(x),
                                                   lambda loc, context: new HttpSymbolServer(URI.create(loc)))

    self.register_symbol_server_instance_creator(200,
                                                   lambda x: SameDirSymbolStore.is_same_dir_location(x),
                                                   lambda loc, context: new SameDirSymbolStore(context.root_dir))

    self.register_symbol_server_instance_creator(300,
                                                   lambda x: LocalSymbolStore.is_local_symbol_store_location(x),
                                                   lambda loc, context: new LocalSymbolStore(new File(loc)))


class SymbolServerInstanceCreator:
    def create_symbol_server_from_location_string(self, symbol_server_location_string, context):
        # implement your logic here
        pass


# usage example:

registry = SymbolServerInstanceCreatorRegistry.get_instance()
context = registry.get_context_with_program(program)
symbol_servers = registry.create_symbol_servers_from_path_list(location_strings, context)

```

Please note that this is a direct translation of the Java code into Python. The functionality and behavior may not be exactly same as in the original Java code due to differences between languages.