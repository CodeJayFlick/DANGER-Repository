class ObsoleteProgramPropertiesService:
    def __init__(self):
        pass

    @classmethod
    def register_service(cls):
        from ghidra.program.database import ObsoleteProgramPropertiesService as service_class
        return service_class()

    @staticmethod
    def get_obsolete_program_properties():
        service = PluggableServiceRegistry.get_pluggable_service(ObsoleteProgramPropertiesService)
        if not service:
            raise ValueError("No registered instance of ObsoleteProgramPropertiesService")
        return service.do_get_obsolete_program_properties()

    def do_get_obsolete_program_properties(self):
        from collections import defaultdict
        return dict()
