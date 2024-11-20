class DbgDebuggerProgramLaunchOpinion:
    def __init__(self):
        pass

    class AbstractDbgDebuggerProgramLaunchOffer:
        def __init__(self, program, tool, factory):
            super().__init__()

        @property
        def menu_parent_title(self):
            return f"Debug {program.name}"

        @property
        def launcher_path(self):
            return []

        @property
        def default_launcher_args(self, params):
            return {"CMDLINE_ARGS_NAME": program.executable_path}

    class InVmDbgengDebuggerProgramLaunchOffer(AbstractDbgDebuggerProgramLaunchOffer):
        FACTORY_CLS_NAME = "agent.dbgeng.DbgEngInJvmDebuggerModelFactory"

        def __init__(self, program, tool, factory):
            super().__init__(program, tool, factory)

        @property
        def config_name(self):
            return "IN-VM dbgeng"

        @property
        def menu_title(self):
            return "in dbgeng locally IN-VM"

    class GadpDbgengDebuggerProgramLaunchOffer(AbstractDbgDebuggerProgramLaunchOffer):
        FACTORY_CLS_NAME = "agent.dbgeng.gadp.DbgEngLocalDebuggerModelFactory"

        def __init__(self, program, tool, factory):
            super().__init__(program, tool, factory)

        @property
        def config_name(self):
            return "GADP dbgeng"

        @property
        def menu_title(self):
            return "in dbgeng locally via GADP"

    class InVmDbgmodelDebuggerProgramLaunchOffer(AbstractDbgDebuggerProgramLaunchOffer):
        FACTORY_CLS_NAME = "agent.dbgmodel.DbgModelInJvmDebuggerModelFactory"

        def __init__(self, program, tool, factory):
            super().__init__(program, tool, factory)

        @property
        def config_name(self):
            return "IN-VM dbgmodel"

        @property
        def menu_title(self):
            return "in dbgmodel locally IN-VM"

    class GadpDbgmodelDebuggerProgramLaunchOffer(AbstractDbgDebuggerProgramLaunchOffer):
        FACTORY_CLS_NAME = "agent.dbgmodel.gadp.DbgModelLocalDebuggerModelFactory"

        def __init__(self, program, tool, factory):
            super().__init__(program, tool, factory)

        @property
        def config_name(self):
            return "GADP dbgmodel"

        @property
        def menu_title(self):
            return "in dbgmodel locally via GADP"

    def get_offers(self, program, tool, service):
        if not program.executable_path:
            return []
        
        offers = []
        for factory in service.model_factories():
            if not factory.is_compatible():
                continue
            cls_name = str(factory.__class__)
            if cls_name == InVmDbgengDebuggerProgramLaunchOffer.FACTORY_CLS_NAME:
                offers.append(InVmDbgengDebuggerProgramLaunchOffer(program, tool, factory))
            elif cls_name == GadpDbgengDebuggerProgramLaunchOffer.FACTORY_CLS_NAME:
                offers.append(GadpDbgengDebuggerProgramLaunchOffer(program, tool, factory))
            elif cls_name == InVmDbgmodelDebuggerProgramLaunchOffer.FACTORY_CLS_NAME:
                offers.append(InVmDbgmodelDebuggerProgramLaunchOffer(program, tool, factory))
            elif cls_name == GadpDbgmodelDebuggerProgramLaunchOffer.FACTORY_CLS_NAME:
                offers.append(GadpDbgmodelDebuggerProgramLaunchOffer(program, tool, factory))

        return offers
