Here is the translation of the Java code into Python:

```Python
class UnionDataType:
    def __init__(self, path, name):
        self.path = path
        self.name = name
        self.components = []

    @property
    def union_length(self):
        return self._union_length

    @union_length.setter
    def union_length(self, value):
        self._union_length = value

    @property
    def union_alignment(self):
        return self._union_alignment

    @union_alignment.setter
    def union_alignment(self, value):
        self._union_alignment = value

    def get_representation(self, buf, settings, length):
        if not self.is_not_yet_defined():
            return "<Empty-Union>"
        else:
            return ""

    def get_component(self, ordinal):
        return self.components[ordinal]

    def get_components(self):
        return self.components[:]

    def get_defined_components(self):
        return self.get_components()

    def get_num_components(self):
        return len(self.components)

    def get_num_defined_components(self):
        return len(self.components)

    def get_preferred_component_length(self, data_type, length):
        if not isinstance(data_type, Dynamic):
            length = -1
        return super().get_preferred_component_length(data_type, length)

    def add(self, data_type, length, name, comment):
        old_alignment = self.union_alignment

        dtc = self.do_add(data_type, length, name, comment)
        if not self.repack(True) and self.is_packing_enabled() and old_alignment != self.union_alignment:
            self.notify_alignment_changed()

        return dtc

    def do_add(self, data_type, length, name, comment):
        data_type = self.validate_data_type(data_type)

        data_type = self.adjust_bit_field(data_type)
        data_type = data_type.clone()
        self.check_ancestry(data_type)

        component = DataTypeComponentImpl(data_type, self, length, len(self.components), 0, name, comment)
        data_type.add_parent(self)
        self.components.append(component)

        return component

    def add_bit_field(self, base_data_type, bit_size, name, comment):
        return self.insert_bit_field(len(self.components), base_data_type, bit_size, name, comment)

    def insert_bit_field(self, ordinal, base_data_type, bit_size, name, comment):
        if ordinal < 0 or ordinal > len(self.components):
            raise IndexOutOfBoundsException(ordinal)

        BitFieldDataType.check_base_data_type(base_data_type)
        base_data_type = base_data_type.clone()

        bitfield_dt = BitFieldDataType(base_data_type, bit_size)
        return self.insert(ordinal, bitfield_dt, bitfield_dt.get_storage_size(), name, comment)

    def is_zero_length(self):
        return self.union_length == 0

    def get_length(self):
        if self.union_length == 0:
            return 1
        else:
            return self.union_length

    def has_language_dependent_length(self):
        # Assume any component may have a language-dependent length
        return True

    def clone(self, dtm):
        union = UnionDataType(self.path, self.name, dtm)
        union.description = self.description
        union.replace_with(self)

        return union

    def copy(self, dtm):
        union = UnionDataType(self.path, self.name, dtm)
        union.description = self.description
        union.replace_with(self)

        return union

    def delete(self, ordinal):
        old_alignment = self.union_alignment

        component = self.components.pop(ordinal)
        component.data_type.remove_parent(self)

        if not self.repack(True) and self.is_packing_enabled() and old_alignment != self.union_alignment:
            self.notify_alignment_changed()

    def repack(self, notify):
        old_length = self.union_length
        old_alignment = self.union_alignment

        self.union_length = 0
        for component in self.components:
            length = component.length
            if self.is_packing_enabled() and isinstance(component.data_type, BitFieldDataType):
                # revise length to reflect compiler bitfield allocation rules
                length = get_bit_field_allocation((BitFieldDataType)component.data_type)
            self.union_length = max(self.union_length, length)

        self.union_alignment = -1  # force recompute of unionAlignment

        if not self.repack(True) and self.is_packing_enabled():
            # NOTE: Must assume alignment change since we are unable to determine
            # without stored alignment
            notify_alignment_changed()

    def is_equivalent(self, dt):
        if dt == this:
            return True
        elif dt is None:
            return False

        if isinstance(dt, UnionInternal):
            union = (UnionInternal)dt

            if self.packing != union.get_stored_packing_value() or \
               self.minimum_alignment != union.get_stored_minimum_alignment():
                # rely on component match instead of checking length
                # since dynamic component sizes could affect length
                return False

            my_comps = self.components[:]
            other_comps = union.components[:]

            if len(my_comps) != len(other_comps):
                return False

            for i in range(len(my_comps)):
                if not my_comps[i].is_equivalent(other_comps[i]):
                    return False

            return True
        else:
            return False

    def data_type_alignment_changed(self, dt):
        if not self.is_packing_enabled():
            return

        changed = False
        for i in range(len(self.components) - 1, -1, -1):  # reverse order
            component = self.components[i]
            remove_bit_field_component = False
            if isinstance(component.data_type, BitFieldDataType):
                bitfield_dt = (BitFieldDataType)component.data_type
                remove_bit_field_component = bitfield_dt.get_base_data_type() == dt

            if remove_bit_field_component or component.data_type == dt:
                dt.remove_parent(self)
                self.components.pop(i)
                changed = True

        if changed and not self.repack(True) and self.is_packing_enabled():
            # NOTE: Must assume alignment change since we are unable to determine
            # without stored alignment
            notify_alignment_changed()

    def data_type_size_changed(self, dt):
        changed = False
        for i in range(len(self.components) - 1, -1, -1):  # reverse order
            component = self.components[i]
            if isinstance(component.data_type, BitFieldDataType):
                bitfield_dt = (BitFieldDataType)component.data_type
                remove_bit_field_component = bitfield_dt.get_base_data_type() == dt

            if remove_bit_field_component or component.data_type == dt:
                if component.length < 0:
                    component.length = dt.length
                else:
                    old_length = component.length
                    new_length = dt.length
                    if new_length > old_length:
                        self.union_alignment = -1  # force recompute of unionAlignment

                changed = True

        if changed and not self.repack(True) and self.is_packing_enabled():
            notify_alignment_changed()

    def data_type_replaced(self, old_dt, new_dt):
        replacement_dt = new_dt
        try:
            validate_data_type(replacement_dt)
            if replacement_dt.data_type_manager != self.data_type_manager:
                replacement_dt = replacement_dt.clone()
            check_ancestry(replacement_dt)

        except Exception as e:
            # TODO: should we use Undefined instead since we do not support DEFAULT in Unions
            replacement_dt = DataType.DEFAULT

        changed = False
        for i in range(len(self.components) - 1, -1, -1):  # reverse order
            component = self.components[i]
            remove_bit_field_component = False
            if isinstance(component.data_type, BitFieldDataType):
                bitfield_dt = (BitFieldDataType)component.data_type
                remove_bit_field_component = bitfield_dt.get_base_data_type() == old_dt

            if remove_bit_field_component or component.data_type == old_dt:
                dtc = self.do_add(replacement_dt, replacement_dt.length, component.name, component.comment)
                changed = True

        if changed and not self.repack(True) and self.is_packing_enabled():
            notify_alignment_changed()

    def data_type_deleted(self, dt):
        changed = False
        for i in range(len(self.components) - 1, -1, -1):  # reverse order
            component = self.components[i]
            remove_bit_field_component = False
            if isinstance(component.data_type, BitFieldDataType):
                bitfield_dt = (BitFieldDataType)component.data_type
                remove_bit_field_component = bitfield_dt.get_base_data_type() == dt

            if remove_bit_field_component or component.data_type == dt:
                dt.remove_parent(self)
                self.components.pop(i)
                changed = True

        if changed and not self.repack(True) and self.is_packing_enabled():
            # NOTE: Must assume alignment change since we are unable to determine
            # without stored alignment
            notify_alignment_changed()

    def replace_with(self, dt):
        if not isinstance(dt, UnionInternal):
            raise ValueError("Invalid replacement type")

        union = (UnionInternal)dt

        for component in self.components:
            component.data_type.remove_parent(self)

        self.components.clear()
        self.union_alignment = -1
        self.packing = union.get_stored_packing_value()
        self.minimum_alignment = union.get_stored_minimum_alignment()

        comp_array = union.components[:]
        for dtc in comp_array:
            do_add(dtc.data_type, dtc.length, dtc.name, dtc.comment)

        repack(False)
        notify_size_changed()  # assume size and/or alignment changed

    def depends_on(self, dt):
        if len(self.components) == 1:
            component = self.get_component(0)
            return component.data_type.depends_on(dt)
        else:
            return False
```

Note that this translation is not perfect as some Java concepts do not have direct Python equivalents. For example, the `@Override` annotation in Java does not exist in Python.