import threading
from collections import defaultdict, deque

class MapModulesDebuggerBot:
    def __init__(self):
        self.plugin = None
        self.listeners = MultiToolTraceListenerManager()
        self.trace_queue = set()
        self.debouncer = AsyncDebouncer(AsyncTimer.DEFAULT_TIMER, 500)
        self.debouncer.add_listener(self.queue_settled)

    @property
    def enabled(self):
        return self.plugin is not None

    def enable(self, plugin: 'DebuggerWorkflowServicePlugin'):
        self.plugin = plugin
        self.listeners.enable(plugin)
        for tool in plugin.get_proxying_plugin_tools():
            trace_manager = tool.get_service(DebuggerTraceManagerService)
            if trace_manager:
                self.queue_traces(trace_manager.get_open_traces())

    def disable(self):
        self.plugin = None
        self.listeners.disable()

    def trace_opened(self, tool: 'PluginTool', trace: 'Trace'):
        self.listeners.trace_opened(tool, trace)
        self.queue_trace(trace)

    def trace_closed(self, tool: 'PluginTool', trace: 'Trace'):
        self.listeners.trace_closed(tool, trace)

    def program_opened(self, t: 'PluginTool', program: 'Program'):
        trace_manager = t.get_service(DebuggerTraceManagerService)
        if trace_manager:
            self.queue_traces(trace_manager.get_open_traces())

    def queue_trace(self, trace):
        with threading.Lock():
            self.trace_queue.add(trace)
        self.debouncer.contact(None)

    def queue_traces(self, traces: 'Collection[ Trace ]'):
        with threading.Lock():
            self.trace_queue.update(traces)
        self.debouncer.contact(None)

    def queue_settled(self, __):
        settled = set()
        with threading.Lock():
            settled = set(self.trace_queue)
            self.trace_queue.clear()

        to_analyze = defaultdict(set)
        for trace in settled:
            for tool in self.plugin.get_proxying_plugin_tools():
                if not trace_manager := tool.get_service(DebuggerTraceManagerService):
                    continue
                program_manager = tool.get_service(ProgramManager)
                if not program_manager:
                    continue
                if not any(t == trace for t in trace_manager.get_open_traces()):
                    continue
                to_analyze[trace].update(program_manager.get_all_open_programs())

        for (trace, programs) in to_analyze.items():
            self.analyze_trace(tool, trace, programs)

    def analyze_trace(self, tool: 'PluginTool', trace: 'Trace', programs):
        cmd = BackgroundCommand("Auto-map modules", True, True, False)
        try:
            mapping_service = tool.get_service(DebuggerStaticMappingService)
            if mapping_service:
                maps = mapping_service.propose_module_maps(
                    trace.module_manager.all_modules,
                    set(programs)
                )
                entries = ModuleMapProposal.flatten(maps.values())
                entries = ModuleMapProposal.remove_overlapping(entries)
                mapping_service.add_module_mappings(entries, None, False)
        except CancelledException:
            return
        tool.execute_background_command(cmd, trace)

class BackgroundCommand:
    def __init__(self, name: str, can_cancel: bool, is_long_running: bool, requires_progress_monitor):
        self.name = name
        self.can_cancel = can_cancel
        self.is_long_running = is_long_running

    def apply_to(self, obj, monitor):
        try:
            # do something
            return True
        except CancelledException:
            return False

class MultiToolTraceListenerManager:
    def __init__(self):
        pass

    def enable(self, plugin: 'DebuggerWorkflowServicePlugin'):
        pass

    def disable(self):
        pass

    def trace_opened(self, tool: 'PluginTool', trace: 'Trace'):
        pass

    def trace_closed(self, tool: 'PluginTool', trace: 'Trace'):
        pass
