class LldbDebuggerProgramLaunchOpinion:
    class AbstractLldbDebuggerProgramLaunchOffer:
        def __init__(self, program, tool):
            pass
        
        @property
        def menu_parent_title(self):
            return f"Debug {program.name}"
        
        @property
        def launcher_path(self):
            return [""]

        @property
        def default_launcher_args(self):
            return {"CMDLINE_ARGS_NAME": program.executable_path}

    class InVmLldbDebuggerProgramLaunchOffer(AbstractLldbDebuggerProgramLaunchOffer):
        FACTORY_CLS_NAME = "agent.lldb.LldbInJvmDebuggerModelFactory"
        
        def __init__(self, program, tool):
            super().__init__(program, tool)
        
        @property
        def config_name(self):
            return "IN-VM LLDB"
        
        @property
        def menu_title(self):
            return "in LLDB locally IN-VM"

    class GadpLldbDebuggerProgramLaunchOffer(AbstractLlldbDebuggerProgramLaunchOffer):
        FACTORY_CLS_NAME = "agent.lldb.gadp.LldbLocalDebuggerModelFactory"
        
        def __init__(self, program, tool):
            super().__init__(program, tool)
        
        @property
        def config_name(self):
            return "GADP LLDB"
        
        @property
        def menu_title(self):
            return "in LLDB locally via GADP"

    def get_offers(self, program, tool, service):
        if not program.executable_path:
            return []
        offers = []
        for factory in service.model_factories:
            if not factory.is_compatible():
                continue
            cls_name = str(factory.__class__)
            if cls_name == InVmLldbDebuggerProgramLaunchOffer.FACTORY_CLS_NAME:
                offers.append(InVmLlldbDebuggerProgramLaunchOffer(program, tool))
            elif cls_name == GadpLlldbDebuggerProgramLaunchOffer.FACTORY_CLS_NAME:
                offers.append(GadpLlldbDebuggerProgramLaunchOffer(program, tool))
        return offers
