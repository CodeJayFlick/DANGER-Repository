class VtShapeTypeApplier:
    def __init__(self, applicator: 'PdbApplicator', ms_type: 'VtShapeMsType') -> None:
        super().__init__()
        self.applicator = applicator
        self.ms_type = ms_type

    @property
    def size(self) -> int:
        return (applicator.data_organization.pointer_size * 
                ms_type.count)

    @property
    def name(self) -> str:
        return f"vtshape_{self.index}"

    def apply(self):
        data_type = self.create_vt_shape(ms_type)
        # TODO: We are creating a structure for the vtshape.  Is there anything different we would 
        # like to do instead?
        return data_type

    def create_vt_shape(self, ms_shape) -> 'DataType':
        list_ = ms_shape.descriptor_list
        shape = StructureDataType(applicator.anonymous_types_category,
                                   f"vtshape_{self.index}", 0, applicator.data_type_manager)
        members = []
        offset = 0
        for descriptor in list_:
            if descriptor in [NEAR, FAR, THIN, OUTER, META, NEAR32, FAR32]:
                pointer = PointerDataType(applicator.data_type_manager)
                member = DefaultPdbUniversalMember(applicator, "", pointer, offset)
                offset += pointer.length
                members.append(member)
            elif descriptor == UNUSED:
                offset += applicator.data_organization.pointer_size

        size = applicator.data_organization.pointer_size * ms_shape.count
        if not DefaultCompositeMember.apply_data_type_members(shape, False, size, members):
            CompositeTypeApplier.clear_components(shape)

        return shape


class PdbApplicator:
    def __init__(self) -> None:
        pass

    @property
    def data_organization(self) -> 'DataOrganization':
        # TODO: implement this property
        pass

    @property
    def anonymous_types_category(self) -> str:
        # TODO: implement this property
        pass

    @property
    def data_type_manager(self) -> 'DataTypeManager':
        # TODO: implement this property
        pass


class VtShapeMsType:
    def __init__(self, count: int):
        self.count = count

    @property
    def descriptor_list(self) -> list['VtShapeDescriptorMsProperty']:
        return []  # TODO: implement this property


class DataOrganization:
    @property
    def pointer_size(self) -> int:
        pass

    @property
    def get_pointer_size(self):
        return self.pointer_size


class DataTypeManager:
    pass


# Enum for VtShapeDescriptorMsProperty
NEAR = 1
FAR = 2
THIN = 3
OUTER = 4
META = 5
UNUSED = 6

# Enum for PdbUniversalMemberType
PDB_UNIVERSAL_MEMBER_TYPE = "PDB UNIVERSAL MEMBER TYPE"
