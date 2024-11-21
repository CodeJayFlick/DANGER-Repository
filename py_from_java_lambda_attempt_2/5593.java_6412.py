Here is the translation of the Java code into Python:

```Python
class MultiListingLayoutModel:
    def __init__(self, format_mgr, programs, primary_addr_set):
        self.format_mgr = format_mgr
        self.primary_addr_set = primary_addr_set
        self.empty_factory = DummyFieldFactory(format_mgr)
        self.cache = LayoutCache()
        self.models = [create_listing_model(programs, i) for i in range(len(programs))]
        self.aligned_models = [AlignedModel(i) for i in range(len(programs))]

    def create_listing_model(self, programs, program_index):
        model = ProgramBigListingModel(programs[program_index], self.format_mgr)
        if program_index != 0:
            model = ListingModelConverter(model, models[0])
        return model

    def get_aligned_model(self, index):
        return self.aligned_models[index]

    def add_layout_listener(self, listener):
        listeners.add(listener)

    def remove_layout_listener(self, listener):
        listeners.remove(listener)

    @property
    def data_changed(self):
        if update_immediately:
            for listener in listeners:
                listener.data_changed(update_immediately)
        return self

    @property
    def model_size_changed(self):
        cache.clear()
        for listener in listeners:
            listener.model_size_changed()

    def get_multi_layout(self, primary_model_address, is_gap):
        if primary_model_address == None:
            return None
        ml = cache.get(primary_model_address)
        if ml == None:
            layouts = [model.get_layout(primary_model_address, is_gap) for model in self.models]
            has_layout = any(layouts)
            if has_layout:
                ml = MultiLayout(layouts, format_mgr, empty_factory)
            else:
                ml = MultiLayout()
            cache.put(primary_model_address, ml)
        return ml

    class AlignedModel:
        def __init__(self, model_id):
            self.model_id = model_id

        @property
        def dispose(self):
            # should be handled by containing class
            pass

        @property
        def get_max_width(self):
            return models[self.model_id].get_max_width()

        @property
        def get_address_after(self, address):
            return self.get_next_address(address, True)

        @property
        def get_address_before(self, address):
            return self.get_next_address(address, False)

        def get_next_address(self, address, after):
            next_address = None  # Next address for this model
            program = models[self.model_id].get_program()
            primary_program = models[0].get_program()
            if program == primary_program:
                primary_model_address = address
            else:
                primary_model_address = SimpleDiffUtility.get_compatible_address(program, address, primary_program)
            # If address is an external from the other model, then we may not be able to get 
            # an equivalent address in the primary model  (i.e. primaryModelAddress may be null)
            if primary_model_address == None:
                return None
            for temp_model in models:
                temp_model_address_after = after and temp_model.get_address_after(primary_model_address) or temp_model.get_address_before(primary_model_address)
                # Convert the tempModelAddress back to address for this model so it can be compared
                if program == temp_model.get_program():
                    address_after = temp_model_address_after
                else:
                    address_after = SimpleDiffUtility.get_compatible_address(temp_model.get_program(), temp_model_address_after, program)
                if address_after == None:
                    continue
                if next_address == None:
                    next_address = address_after
                    continue
                result = address_after.compare(next_address)
                is_next_address = after and result < 0 or result > 0
                if is_next_address:
                    next_address = address_after
            return next_address

        @property
        def get_layout(self, this_model_address, is_gap):
            primary_model_address = self.model_id == 0 and this_model_address or SimpleDiffUtility.get_compatible_address(get_program(), this_model_address, models[0].get_program())
            ml = get_multi_layout(primary_model_address, is_gap)
            if ml != None:
                return ml.get_layout(self.model_id)
            return None

        def add_listener(self, listener):
            self.add_layout_listener(listener)

        def remove_listener(self, listener):
            self.remove_layout_listener(listener)

        @property
        def get_program(self):
            return models[self.model_id].get_program()

        # Other methods...
```

Note: This translation is not perfect and may require some adjustments to work correctly in Python.