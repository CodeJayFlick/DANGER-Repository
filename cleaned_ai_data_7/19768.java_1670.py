import java_to_python as jtp

# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

class GriefPreventionHook:
    def __init__(self):
        pass

    supports_uuids = None
    get_claim_method = None
    claims_field = None

    @staticmethod
    def init(self):
        self.supports_uuids = jtp.Skript.field_exists(Claim, 'ownerID')
        try:
            method = DataStore.__dict__['getClaim']
            method.setAccessible(True)
            if not Claim in get_claim_method.return_type():
                get_claim_method = None
        except (NoSuchMethodException, SecurityException):
            pass

        try:
            field = DataStore.__dict__['claims']
            field.setAccessible(True)
            if not List in field.type():
                claims_field = None
        except (NoSuchFieldException, SecurityException):
            pass

        if get_claim_method is None and claims_field is None:
            jtp.Skript.error("Skript " + jtp.Skript.get_version() +
                             " is not compatible with GriefPrevention " +
                             plugin.__dict__['description'].get_version() +
                             ". Please report this at https://github.com/SkriptLang/Skript/issues/ if this error occurred after you updated GriefPrevention.")
            return False
        else:
            return super().__init__()

    @staticmethod
    def get_claim(self, id):
        if self.get_claim_method is not None:
            try:
                claim = self.get_claim_method.invoke(self.plugin.data_store, id)
                return Claim(claim)
            except (IllegalAccessException, IllegalArgumentException, InvocationTargetException) as e:
                assert False, str(e)

        else:
            claims = jtp.Collections.list(jtp.DataStore.__dict__['claims'].get(self.plugin.data_store))
            for claim in claims:
                if isinstance(claim, Claim):
                    if claim.get_id() == id:
                        return claim
            return None

    @staticmethod
    def get_name(self):
        return "GriefPrevention"

    @staticmethod
    def can_build_ii(self, p, l):
        return self.plugin.allow_build(p, l) is None  # returns reason string if not allowed to build

class GriefPreventionRegion:
    def __init__(self, claim):
        self.claim = claim

    @staticmethod
    def contains(self, location):
        return self.claim.contains(location, False, False)

    @staticmethod
    def is_member(self, p):
        name = p.name if p else None
        if name:
            return jtp.String(name).lower() == jtp.String(self.claim.get_owner_name()).lower()
        return False  # Assume no ownership when player has never visited server

    @staticmethod
    def get_members(self):
        if self.claim.is_admin_claim():
            return []
        elif self.supports_uuids:
            owner = jtp.Bukkit.get_offline_player(self.claim.owner_id)
            return [owner] if owner else []

        name = self.claim.get_owner_name()
        owners = jtp.Collections.list([jtp.Bukkit.get_offline_player(name)])
        return owners

    @staticmethod
    def get_owners(self):
        if self.claim.is_admin_claim() or (self.supports_uuids and self.claim.owner_id is None):  # Not all claims have owners!
            return []

        elif self.supports_uuids:
            owner = jtp.Bukkit.get_offline_player(self.claim.owner_id)
            return [owner] if owner else []

        else:
            name = self.claim.get_owner_name()
            owners = jtp.Collections.list([jtp.Bukkit.get_offline_player(name)])
            return owners

    @staticmethod
    def get_blocks(self):
        lower = self.claim.get_lesser_boundary_corner()
        upper = self.claim.get_greater_boundary_corner()

        if (lower is None or upper is None) or (lower.world is None or upper.world is None) or (lower.world != upper.world):
            return jtp.EmptyIterator

        upper.set_y(upper.world.max_height - 1)
        upper.set_x(upper.block_x)
        upper.set_z(upper.block_z)

        return self.claim.get_lesser_boundary_corner().world.chunk_iterator()

    @staticmethod
    def __str__(self):
        return "Claim #{}".format(self.claim.id)

    @staticmethod
    def serialize(self):
        fields = jtp.Fields()
        fields.put_primitive("id", self.claim.id)
        return fields

    @staticmethod
    def deserialize(self, fields):
        id = fields.get_primitive("id")
        claim = GriefPreventionHook.get_claim(id)
        if claim is None:
            raise jtp.StreamCorruptedException("Invalid claim {}".format(id))
        self.claim = claim

class RegionsPlugin(GriefPreventionHook):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
