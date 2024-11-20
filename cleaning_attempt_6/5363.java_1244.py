from typing import Callable, Optional

class LoadSpecChooser:
    def __init__(self):
        pass

    @staticmethod
    def choose(loader_map: dict) -> Optional['LoadSpec']:
        """Chooses a LoadSpec for a Loader to use based on some criteria"""
        preferred_load_specs = [load_spec for load_spec in loader_map.values() if load_spec is not None and load_spec.is_preferred()]
        return next((load_spec for load_spec in preferred_load_specs), None)

    @staticmethod
    def CHOOSE_THE_FIRST_PREFERRED() -> Callable[[dict], Optional['LoadSpec']]:
        """Chooses the first "preferred" LoadSpec"""
        return lambda loader_map: next((load_spec for load_spec in loader_map.values() if load_spec is not None and load_spec.is_preferred()), None)
