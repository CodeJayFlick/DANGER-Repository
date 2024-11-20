import asyncio
from typing import Any

class DbgModelInJvmDebuggerModelFactory:
    def __init__(self):
        pass

    async def build(self) -> Any:
        from dbgmodel.model.impl import DbgModel2Impl  # Assuming this is a module name and class name in your Python code
        model = DbgModel2Impl()
        return await model.start_dbg_eng([])

    def is_compatible(self):
        os_name = os.environ.get('os.name', '').lower()
        return 'windows' in os_name

# You can use this factory to create a debugger object:
factory = DbgModelInJvmDebuggerModelFactory()
model = asyncio.run(factory.build())
