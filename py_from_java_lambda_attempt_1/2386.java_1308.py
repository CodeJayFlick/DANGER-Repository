Here is your Java code translated into Python:

```Python
class DBTraceDefinedDataView:
    def __init__(self, space):
        super().__init__()

    def create(self, lifespan: Range[int], address: int, data_type: str) -> None:
        pass  # NOTE: "Adapter" because using DataType.DEFAULT gives UndefinedDBTraceData

    def is_function_definition(self, dt: str) -> bool:
        if isinstance(dt, FunctionDefinition):
            return True
        elif isinstance(dt, TypeDef):
            type_def = (TypeDef)(dt)
            return self.is_function_definition(type_def.get_base_data_type())
        else:
            return False

    @staticmethod
    def lower_endpoint(lifespan: Range[int]) -> int:
        pass  # NOTE: User-given length could be ignored.... Check start address first. After I know length, I can check for other existing units

    @staticmethod
    def truncate_soonest_defined(lifespan: Range[int], created_range: AddressRange) -> None:
        if not lifespan.has_upper_bound():
            lifespan = space.instructions.truncate_soonest_defined(lifespan, created_range)
            lifespan = space.defined_data.truncate_soonest_defined(lifespan, created_range)

    @staticmethod
    def first_change(lifespan: Range[int], created_range: AddressRange) -> int:
        pass  # NOTE: This pointer will need to be sensitive to the unit's language.

    @staticmethod
    def upper_endpoint(lifespan: Range[int]) -> int:
        return DBTraceDefinedDataView.lower_endpoint(lifespan)

    def create(self, lifespan: Range[int], address: int, orig_type: str, length: int) -> None:
        try:
            mem_space = space.memory_manager.get(space, True)
            start_snap = self.lower_endpoint(lifespan)
            if not space.undefined_data.covers_range(Range.closed(start_snap, start_snap), AddressRange(address, address)):
                raise CodeUnitInsertionException("Code units cannot overlap")

            data_type; length
            if isinstance(orig_type, FactoryDataType):
                buffer = mem_space.get_buffer_at(start_snap, address)
                factory_data_type = (FactoryDataType)(orig_type)
                data_type = factory_data_type.get_data_type(buffer)
                length = -1
            else:
                data_type = orig_type
                length = orig_length

            if data_type is None:
                raise CodeUnitInsertionException("Failed to resolve data type")

            # TODO: This clone may need to be sensitive to the unit's language.
            data_type = data_type.clone(space.data_type_manager)

            if self.is_function_definition(data_type):
                # TODO: This pointer will need to be sensitive to the unit's language.
                data_type = PointerDataType(data_type, data_type.get_data_type_manager())
                length = data_type.get_length()
            elif isinstance(data_type, Dynamic):
                dynamic = (Dynamic)(data_type)
                buffer = mem_space.get_buffer_at(start_snap, address)
                length = dynamic.get_length(buffer, length)
            else:
                length = data_type.get_length()

            if length < 0:
                raise CodeUnitInsertionException(f"Failed to resolve data length for {orig_type.name}")

            end_address = address.add_no_wrap(length - 1)
            created_range = AddressRange(address, end_address)

            # First, truncate lifespan to the next unit in the range, if end is unbounded
            self.truncate_soonest_defined(lifespan, created_range)

            # Second, extend to the next change of bytes in the range within lifespan
            end_snap = mem_space.get_first_change(lifespan, created_range)
            if end_snap == int.min_value:
                end_snap = DBTraceDefinedDataView.upper_endpoint(lifespan)
            else:
                end_snap -= 1

            tasr = ImmutableTraceAddressSnapRange(created_range,
                                                    Range.closed(start_snap, end_snap))
            if not space.undefined_data.covers_range(tasr):
                raise CodeUnitInsertionException("Code units cannot overlap")

            created = space.data_map_space.put(tasr, None)
            created.set(space.base_language, data_type)

        except AddressOverflowException as e:
            raise CodeUnitInsertionException(f"Could unit would extend beyond address space: {e}")

    def unit_removed(self, unit):
        super().unit_removed(unit)
        if isinstance(data_type := unit.get_base_data_type(), (Composite, Array, Dynamic)):
            self.space.trace.set_changed(TraceChangeRecord(TraceCompositeDataChangeType.REMOVED,
                                                             self.space, unit.bounds, unit))

    def unit_span_changed(self, old_span: Range[int], unit):
        super().unit_span_changed(old_span, unit)
        if isinstance(data_type := unit.get_base_data_type(), (Composite, Array, Dynamic)):
            self.space.trace.set_changed(TraceChangeRecord(TraceCompositeDataChangeType.LIFESPAN_CHANGED,
                                                             self.space, unit, old_span, unit.lifespan))
```

Please note that I have not tested this code.