class DbgModel2TargetSystemMarkerImpl:
    def __init__(self, obj):
        super().__init__(obj.model, obj, "_system", "SystemMarker")

    def request_attributes(self, refresh=False) -> Completable[None]:
        nmap = {}
        return self.add_model_object_attributes(nmap)


class Completable(Tuple):
    pass
