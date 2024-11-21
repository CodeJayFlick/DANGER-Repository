class TestDummyGoToService:
    def __init__(self):
        pass

    def go_to(self, loc: 'ProgramLocation') -> bool:
        # stub
        return False

    def go_to(self, loc: 'ProgramLocation', program: 'Program') -> bool:
        # stub
        return False

    def go_to(self, navigatable: 'Navigatable', loc: 'ProgramLocation', program: 'Program') -> bool:
        # stub
        return False

    def go_to(self, navigatable: 'Navigatable', program: 'Program', address1: 'Address', 
              address2: 'Address') -> bool:
        # stub
        return False

    def go_to(self, current_address: 'Address', goTo_address: 'Address') -> bool:
        # stub
        return False

    def go_to(self, navigatable: 'Navigatable', goTo_address: 'Address') -> bool:
        # stub
        return False

    def go_to(self, goTo_address: 'Address') -> bool:
        # stub
        return False

    def go_to(self, goTo_address: 'Address', program: 'Program') -> bool:
        # stub
        return False

    def go_to_external_location(self, external_loc: 'ExternalLocation', 
                                  check_navigation_option: bool) -> bool:
        # stub
        return False

    def go_to_external_location(self, navigatable: 'Navigatable', external_loc: 'ExternalLocation', 
                                 check_navigation_option: bool) -> bool:
        # stub
        return False

    def go_to_query(self, from_addr: 'Address', query_data: 'QueryData', listener: 'GoToServiceListener', 
                     monitor: 'TaskMonitor') -> bool:
        # stub
        return False

    def go_to_query(self, navigatable: 'Navigatable', from_addr: 'Address', query_data: 'QueryData', 
                     listener: 'GoToServiceListener', monitor: 'TaskMonitor') -> bool:
        # stub
        return False

    def get_override_service(self) -> 'GoToOverrideService':
        # stub
        return None

    def set_override_service(self, override: 'GoToOverrideService'):
        # stub

    def get_default_navigatable(self) -> 'Navigatable':
        # stub
        return None
