Here is the translation of the Java code into Python:

```Python
import Residence
from yggdrasil import YggdrasilID

class ResidenceHook:
    def __init__(self):
        pass

    def init(self):
        return super().init()

    @YggdrasilID("ResidenceRegion")
    class ResidenceRegion(RegionsPlugin):
        def __init__(self, world, res):
            self.res = res
            self.world = world

        def serialize(self):
            f = Fields()
            f.put_object("region", self.res.name)
            return f

        def deserialize(self, fields):
            region = fields.get_object("region")
            if not isinstance(region, str):
                raise StreamCorruptedException(
                    "Tried to deserialize Residence region with no valid name!"
                )
            res = Residence.getInstance().getResidenceManager().get_by_name((str) region)
            if res is None:
                raise StreamCorruptedException(
                    f"Invalid region {region} in world {self.world}"
                )
            self.res = res

        def contains(self, l):
            return self.res.contains_loc(l)

        def is_member(self, p):
            return self.res.get_permissions().player_has(p.name, Flags.build, False)

        def get_members(self):
            return []

        def is_owner(self, p):
            return self.res.get_permissions().get_owner_uuid() == p.unique_id

        def get_owners(self):
            return [Residence.getInstance().get_offline_player(self.res.get_permissions().get_owner())]

        def get_blocks(self):
            return iter([])

        def __str__(self):
            return f"{self.res.name} in world {self.world.name}"

        def get_plugin(self):
            return self

        def __eq__(self, o):
            if o is self:
                return True
            if not isinstance(o, ResidenceRegion):
                return False
            if hash(o) == self.hash():
                return True
            return False

        def __hash__(self):
            return self.res.name.__hash__()
```

Please note that this translation may require some adjustments to work correctly in a Python environment.