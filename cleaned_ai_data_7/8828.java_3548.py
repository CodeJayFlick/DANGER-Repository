from enum import Enum

class VTProgramCorrelatorAddressRestrictionPreference(Enum):
    NO_PREFERENCE = 0
    RESTRICTION_NOT_ALLOWED = 1
    PREFER_RESTRICTING_ACCEPTED_MATCHES = 2
