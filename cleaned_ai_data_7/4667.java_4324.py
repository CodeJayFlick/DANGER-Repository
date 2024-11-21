class DWARFUtil:
    OPERATOR_LT_STR = "operator<"
    OPERATOR_LSHIFT_STR = "operator<<"

    def __init__(self):
        pass

    @staticmethod
    def to_string(clazz, value):
        return DWARFUtil.to_string(clazz, Conv.int_to_long(value))

    @staticmethod
    def to_string(clazz, value):
        field = DWARFUtil.get_static_final_field_with_value(clazz, value)
        if field is not None:
            return field.name
        else:
            return "Unknown DWARF Value: 0x" + hex(value)

    @staticmethod
    def get_static_final_field_with_value(clazz, value):
        fields = clazz.getDeclaredFields()
        for i in range(len(fields)):
            if (not Modifier.isFinal(fields[i].getModifiers()) or not Modifier.isStatic(fields[i].getModifiers())):
                continue
            try:
                field_value = fields[i].getLong(None)
                if field_value == value:
                    return fields[i]
            except (IllegalArgumentException, IllegalAccessException):
                pass
        return None

    @staticmethod
    def get_container_type_name(diea):
        switch diea.tag:
            case DWARFTag.DW_TAG_structure_type | DWARFTag.DW_TAG_class_type | \
                 DWARFTag.DW_TAG_union_type | DWARFTag.DW_TAG_enumeration_type:
                return "class"
            case DWARFTag.DW_TAG_subprogram:
                return "subr"
        return "unknown"

    @staticmethod
    def parse_mangled_nestings(s):
        results = []
        matcher = Pattern.compile("(.*_Z)?N([0-9]+.*)").matcher(s)
        if not matcher.matches():
            return results
        s = matcher.group(2)

        cp = 0
        while cp < len(s):
            start = cp
            while Character.isDigit(s[cp]) and cp < len(s):
                cp += 1
            if start == cp:
                break
            length = int(s[start:cp])
            if cp + length <= len(s):
                name = s[cp:cp+length]
                results.append(name)
            cp += length

        return results

    @staticmethod
    def find_linkage_name_in_children(diea):
        prog = diea.get_program()
        for child_die in diea.get_children(DWARFTag.DW_TAG_subprogram):
            if child_die.tag == DWARFTag.DW_TAG_ subprogram:
                linkage = child_die.get_string(DWARFAttribute.DW_AT_linkage_name, None)
                if linkage is not None:
                    return parse_mangled_nestings(linkage)

        return []

    @staticmethod
    def get_template_base_name(name):
        start_of_template = name.find('<', name.startswith(OPERATOR_LSHIFT_STR) and len(OPERATOR_LSHIFT_STR) or 0)
        if start_of_template > 0 and name.find('>') > 0:
            return name[:start_of_template].strip()
        else:
            return None

    @staticmethod
    def get_anon_name_for_me_from_parent_context(diea):
        parent = diea.get_head_fragment().get_parent()
        if parent is not None:
            type_def_count = 0
            for child_die in parent.get_children():
                if child_die == diea:
                    return "anon_" + DWARFUtil.get_container_type_name(child_die) + "_" + str(type_def_count)
                elif child_die.is_named_type():
                    type_def_count += 1

        raise RuntimeException("Could not find child in parent's list of children: child:" + str(diea) + ",\nparent:" + str(parent))

    @staticmethod
    def get_anon_name_for_me_from_parent_context2(diea):
        parent = diea.get_head_fragment().get_parent()
        if parent is None:
            return None

        users = []
        for child_die in parent.get_children():
            if child_die == diea and child_die.name is not None:
                users.append(child_die.name)

        Collections.sort(users)
        if len(users) > 0:
            sb = StringBuilder()
            for user_name in users:
                if sb.length > 0:
                    sb.append("_")
                sb.append(user_name)
            return "anon_" + DWARFUtil.get_container_type_name(diea) + "_for_" + str(sb)

        return None

    @staticmethod
    def get_lexical_block_name(diea):
        return "lexical_block" + DWARFUtil.get_lexical_block_name_worker(diea.get_head_fragment())

    @staticmethod
    def get_lexical_block_name_worker(die):
        if die.tag == DWARFTag.DW_TAG_lexical_block or die.tag == DWARFTag.DW_TAG_inlined_subroutine:
            return str(get_my_position_in_parent(die)) + "_"
        else:
            return ""

    @staticmethod
    def get_my_position_in_parent(die):
        parent = die.get_parent()
        if parent is not None:
            position = 0
            for child_die in parent.get_children():
                if child_die == die:
                    return position

                position += 1

        return -1

    @staticmethod
    def append_description(dt, description, sep):
        if description is None or len(description) == 0:
            return

        prev = dt.description
        if prev is not None and len(prev) > 0:
            prev += sep + " "

        dt.description = prev + description

    @staticmethod
    def read_offset_by_dwarf_format(reader, dwarf_format):
        switch dwarf_format:
            case DWARFCompilationUnit.DWARF_32:
                return reader.read_next_unsigned_int()
            case DWARFCompilationUnit.DWARF_64:
                return reader.read_next_long()

        raise IOException("Unknown DWARF Format Value: " + str(dwarf_format))

    @staticmethod
    def read_var_sized_ulong(reader, pointer_size):
        switch pointer_size:
            case 1:
                return reader.read_next_unsigned_byte()
            case 2:
                return reader.read_next_unsigned_short()
            case 4:
                return reader.read_next_unsigned_int()

        raise IOException("Unsupported variable-sized int: " + str(pointer_size))

    @staticmethod
    def read_address(reader, pointer_size):
        switch pointer_size:
            case 1:
                return Byte.valueOf(reader.read_next_byte())
            case 2:
                return Short.valueOf(reader.read_next_short())
            case 4:
                return Integer.valueOf(reader.read_next_int())

        raise IOException("Unknown pointer size: " + str(pointer_size))

    @staticmethod
    def is_this_param(param_diea):
        if param_diea.get_bool(DWARFAttribute.DW_AT_artificial, False) or "this" == param_diea.name:
            return True

        dw_at_object_pointer = param_diea.parent().get_attribute(DWARFAttribute.DW_AT_object_ pointer)
        return isinstance(dw_at_object_pointer, DWARFNumericAttribute) and param_diea.has_offset(((DWARFNumericAttribute)dw_at_object_pointer).get_unsigned_value())

    @staticmethod
    def get_referring_typedef(diea):
        if diea is None:
            return None

        referers = list()
        for child_die in diea.get_children(DWARFTag.DW_TAG_TYPEDEF):
            referers.append(child_die)

        return (referers.size() == 1) and referers[0] or None
