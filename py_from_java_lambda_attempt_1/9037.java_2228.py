Here is the translation of the Java code into Python:

```Python
class VTRelatedMatchType:
    TARGET_MATCHES_TARGET_ACCEPTED = (VTRelatedMatchCorrelationType.TARGET,
                                       VTRelatedMatchCorrelationType.TARGET,
                                       VTAssociationStatus.ACCEPTED, 100)
    CALLER_MATCHES_CALLER_ACCEPTED = (VTRelatedMatchCorrelationType.CALLER,
                                       VTRelatedMatchCorrelationType.CALLER,
                                       VTAssociationStatus.ACCEPTED, 90)
    CALLEE_MATCHES_CALLEE_ACCEPTED = (VTRelatedMatchCorrelationType.CALLEE,
                                       VTRelatedMatchCorrelationType.CALLEE,
                                       VTAssociationStatus.ACCEPTED, 90)

    TARGET_MATCHES_TARGET_AVAILABLE = (VTRelatedMatchCorrelationType.TARGET,
                                        VTRelatedMatchCorrelationType.TARGET,
                                        VTAssociationStatus.AVAILABLE, 80)
    CALLER_MATCHES_CALLER_AVAILABLE = (VTRelatedMatchCorrelationType.CALLER,
                                       VTRelatedMatchCorrelationType.CALLER,
                                       VTAssociationStatus.AVAILABLE, 80)
    CALLEE_MATCHES_CALLEE_AVAILABLE = (VTRelatedMatchCorrelationType.CALLEE,
                                       VTRelatedMatchCorrelationType.CALLEE,
                                       VTAssociationStatus.AVAILABLE, 80)

    CALLER_MATCHES_TARGET_ACCEPTED = (VTRelatedMatchCorrelationType.CALLER,
                                      VTRelatedMatchCorrelationType.TARGET,
                                      VTAssociationStatus.ACCEPTED, 70)
    CALLEE_MATCHES_TARGET_ACCEPTED = (VTRelatedMatchCorrelationType.CALLEE,
                                       VTRelatedMatchCorrelationType.TARGET,
                                       VTAssociationStatus.ACCEPTED, 70)

    TARGET_MATCHES_CALLER_BLOCKED_OUT = (VTRelatedMatchCorrelationType.TARGET,
                                          VTRelatedMatchCorrelationType.CALLER,
                                          VTAssociationStatus.BLOCKED, 60)
    CALLEE_MATCHES_CALLEE_BLOCKED_OUT = (VTRelatedMatchCorrelationType.CALLEE,
                                         VTRelatedMatchCorrelationType.CALLEE,
                                         VTAssociationStatus.BLOCKED, 60)

    CALLER_MATCHES_CALLEE_ACCEPTED = (VTRelatedMatchCorrelationType.CALLER,
                                      VTRelatedMatchCorrelationType.CALLEE,
                                      VTAssociationStatus.ACCEPTED, 50)
    CALLEE_MATCHES_CALLER_ACCEPTED = (VTRelatedMatchCorrelationType.CALLEE,
                                       VTRelatedMatchCorrelationType.CALLER,
                                       VTAssociationStatus.ACCEPTED, 50)

    TARGET_MATCHES_TARGET_BLOCKED_OUT = (VTRelatedMatchCorrelationType.TARGET,
                                          VTRelatedMatchCorrelationType.TARGET,
                                          VTAssociationStatus.BLOCKED, 0)
    CALLER_MATCHES_CALLER_ACCEPTED = (VTRelatedMatchCorrelationType.CALLER,
                                       VTRelatedMatchCorrelationType.CALLER,
                                       VTAssociationStatus.ACCEPTED, 20)

    def __init__(self, source_type, destination_type, association_status):
        self.source_type = source_type
        self.destination_type = destination_type
        self.association_status = association_status

    @classmethod
    def find_match_type(cls, source_type, destination_type, association_status):
        for value in cls.__dict__.values():
            if isinstance(value, tuple) and len(value) == 4:
                if (value[0] == source_type and 
                    value[1] == destination_type and 
                    value[2] == association_status):
                    return VTRelatedMatchType(*value)
        return None

    def get_source_type(self):
        return self.source_type

    def get_destination_type(self):
        return self.destination_type

    def get_association_status(self):
        return self.association_status
```

Please note that this code is not a direct translation of the Java code, but rather an equivalent Python implementation. The `VTRelatedMatchCorrelationType` and `VTAssociationStatus` classes are assumed to be defined elsewhere in your Python program.