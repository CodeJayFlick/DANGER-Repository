import asyncio

class DbgModuleImpl:
    def __init__(self, manager: 'DbgManagerImpl', process: 'DbgProcessImpl', info: DebugModuleInfo):
        self.manager = manager
        self.process = process
        self.info = info
        self.name = info.module_name

    @property
    def name(self) -> str:
        return self.name

    async def add(self):
        await asyncio.create_task(self.process.add_module(self))
        await asyncio.create_task(self.manager.get_event_listeners().fire_module_loaded(self.process, self.info))

    async def remove(self):
        await asyncio.create_task(self.process.remove_module(self.name))
        await asyncio.create_task(self.manager.get_event_listeners().fire_module_unloaded(self.process, self.info))

    @property
    def image_name(self) -> str:
        return self.info.image_name if self.info else self.name

    @property
    def module_name(self) -> str:
        return self.info.module_name if self.info else self.name

    @property
    def known_base(self) -> int:
        return 0 if not self.info else self.info.base_offset

    @property
    def size(self) -> int:
        return 0 if not self.info else self.info.module_size

    @property
    def time_stamp(self) -> int:
        return 0 if not self.info else self.info.time_date_stmp

    async def list_minimal_symbols(self):
        return await asyncio.create_task(self.manager.execute(DbgListSymbolsCommand(self.manager, self.process, self)))

class DebugModuleInfo:
    def __init__(self, module_name: str, image_name: str, base_offset: int, module_size: int, time_date_stmp: int):
        self.module_name = module_name
        self.image_name = image_name
        self.base_offset = base_offset
        self.module_size = module_size
        self.time_date_stmp = time_date_stmp

class DbgManagerImpl:
    def __init__(self):
        pass

    async def execute(self, command: 'DbgListSymbolsCommand'):
        # TO DO: implement the execution logic here
        return None

class DbgProcessImpl:
    def __init__(self):
        pass

    async def add_module(self, module: 'DbgModuleImpl'):
        # TO DO: implement the adding of a module to the process here
        pass

    async def remove_module(self, name: str):
        # TO DO: implement the removing of a module from the process here
        pass

class DbgListSymbolsCommand:
    def __init__(self, manager: 'DbgManagerImpl', process: 'DbgProcessImpl', module: 'DbgModuleImpl'):
        self.manager = manager
        self.process = process
        self.module = module
