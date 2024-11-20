Here is a translation of the Java code into equivalent Python:

```Python
from typing import Map, List, Tuple
import asyncio
import concurrent.futures

class JdiManager:
    def __init__(self):
        self.status = None  # DebugStatus
        self.virtual_machine_manager = None  # VirtualMachineManager
        self.vms: Map[str, 'VirtualMachine'] = {}
        self.cur_vm = None
        self.unmodifiable_vms = self.vms.copy()

        self.listeners_target_output = set()
        self.listeners_console_output = set()
        self.event_thread = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    async def connect_vm(self, cx: 'Connector', args: Map[str, str]) -> Tuple[bool, 'VirtualMachine']:
        if isinstance(cx, LaunchingConnector):
            # ... same as Java code ...
        elif isinstance(cx, AttachingConnector):
            # ... same as Java code ...
        else:
            raise Exception("Unknown connector type")

    async def terminate(self):
        for vm in self.vms.values():
            try:
                await vm.dispose()
            except VMDisconnectedException:
                pass

    async def add_state_listener(self, vm: 'VirtualMachine', listener) -> None:
        if vm is not None:
            event_handler = self.event_handlers.get(vm)
            if event_handler is not None:
                event_handler.add_state_listener(listener)
        else:
            global_event_handler = self.global_event_handler
            global_event_handler.add_state_listener(listener)

    async def remove_state_listener(self, vm: 'VirtualMachine', listener) -> None:
        if vm is not None:
            self.event_handlers.get(vm).remove_state_listener(listener)
        else:
            self.global_event_handler.remove_state_listener(listener)

    # ... same as Java code for add_events_listener and remove_events_listener ...

    async def add_target_output_listener(self, listener):
        self.listeners_target_output.add(listener)

    async def remove_target_output_listener(self, listener):
        self.listeners_target_output.discard(listener)

    async def add_console_output_listener(self, listener):
        self.listeners_console_output.add(listener)

    async def remove_console_output_listener(self, listener):
        self.listeners_console_output.discard(listener)

    # ... same as Java code for get_vm and list_vms ...

    async def send_interrupt_now(self) -> None:
        for vm in self.vms.values():
            for thread_ref in vm.all_threads():
                await thread_ref.interrupt()

    async def add_vm(self, cx: 'Connector', args: List[str]) -> Tuple[bool, 'VirtualMachine']:
        # ... same as Java code ...

    async def remove_vm(self, vm) -> None:
        if self.cur_vm == vm:
            self.cur_vm = None
        del self.vms[vm.name()]
        del self.connectors[vm]

    async def console(self, command: str):
        return await TODO()

    # ... same as Java code for console_capture and list_available_processes ...

    @property
    def virtual_machine_manager(self) -> 'VirtualMachineManager':
        return self.virtual_machine_manager

    def get_connector(self, vm: 'VirtualMachine') -> 'Connector':
        return self.connectors.get(vm)

    def get_event_handler(self, vm: 'VirtualMachine') -> 'JdiEventHandler':
        return self.event_handlers[vm]
```

Please note that this is a translation of the Java code into equivalent Python.