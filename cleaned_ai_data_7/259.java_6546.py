import asyncio
from typing import List, Dict

class DefaultDataTypeRecorder:
    def __init__(self):
        self.trace = None  # Initialize trace variable
        self.type_converter = TargetDataTypeConverter()  # Create type converter instance

    async def capture_data_types(self, namespace: 'TargetDataTypeNamespace', monitor: 'TaskMonitor') -> asyncio.Future:
        path = PathUtils().to_string(namespace.get_path())
        monitor.set_message(f"Capturing data types for {path}")
        return (namespace.get_types()
                .thenCompose(lambda types: (
                    monitor.initialize(len(types))
                    for _ in types
                    yield from self._capture_data_types(type_converter, namespace, monitor)
                ))
                .thenAccept(converted -> (
                    if converted is None:
                        return
                    try:
                        with RecorderPermanentTransaction(self.trace, f"Capture data types for {path}"):
                            category = self.trace.get_data_type_manager().create_category(f"/{path}")
                            for data_type in converted:
                                category.add_data_type(data_type, DataTypeConflictHandler.DEFAULT_HANDLER)
                    except Exception as e:
                        print(f"Error: {e}")
                ))
    )

    async def capture_data_types(self, target_module: 'TargetModule', monitor: 'TaskMonitor') -> asyncio.Future:
        future = await (target_module.fetch_children_supporting(TargetDataTypeNamespace))
        return (
            for namespace in future.values():
                yield from self.capture_data_types(namespace, monitor)
        )
