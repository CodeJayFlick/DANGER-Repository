class GdbDebuggerProgramLaunchOpinion:
    class AbstractGdbDebuggerProgramLaunchOffer:
        def __init__(self, program, tool, factory):
            pass

        def getMenuParentTitle(self):
            return f"Debug {program.name}"

        def getLauncherPath(self):
            return ["Inferiors[1]"]

        def generateDefaultLauncherArgs(self, params):
            return {"CMDLINE_ARGS_NAME": program.executable_path}

    class InVmGdbDebuggerProgramLaunchOffer(AbstractGdbDebuggerProgramLaunchOffer):
        FACTORY_CLS_NAME = "agent.gdb.GdbInJvmDebuggerModelFactory"

        def __init__(self, program, tool, factory):
            super().__init__(program, tool, factory)

        def getConfigName(self):
            return "IN-VM GDB"

        def getMenuTitle(self):
            return "in GDB locally IN-VM"

    class GadpGdbDebuggerProgramLaunchOffer(AbstractGdbDebuggerProgramLaunchOffer):
        FACTORY_CLS_NAME = "agent.gdb.gadp.GdbLocalDebuggerModelFactory"

        def __init__(self, program, tool, factory):
            super().__init__(program, tool, factory)

        def getConfigName(self):
            return "GADP GDB"

        def getMenuTitle(self):
            return "in GDB locally via GADP"

    class SshGdbDebuggerProgramLaunchOffer(AbstractGdbDebuggerProgramLaunchOffer):
        FACTORY_CLS_NAME = "agent.gdb.GdbOverSshDebuggerModelFactory"

        def __init__(self, program, tool, factory):
            super().__init__(program, tool, factory)

        def getConfigName(self):
            return "SSH GDB"

        def getQuickTitle(self):
            opts = factory.get_options()
            return f"in GDB via ssh:{opts['SSH username'].value}@{opts['SSH hostname'].value}"

        def getMenuTitle(self):
            return "in GDB via ssh"

    def get_offers(self, program, tool, service):
        if not program.executable_path:
            return []
        
        offers = []
        for factory in service.model_factories:
            if not factory.is_compatible():
                continue
            cls_name = str(factory.__class__)
            if cls_name == InVmGdbDebuggerProgramLaunchOffer.FACTORY_CLS_NAME:
                offers.append(InVmGdbDebuggerProgramLaunchOffer(program, tool, factory))
            elif cls_name == GadpGdbDebuggerProgramLaunchOffer.FACTORY_CLS_NAME:
                offers.append(GadpGdbDebuggerProgramLaunchOffer(program, tool, factory))
            elif cls_name == SshGdbDebuggerProgramLaunchOffer.FACTORY_CLS_NAME:
                offers.append(SshGdbDebuggerProgramLaunchOffer(program, tool, factory))

        return offers
