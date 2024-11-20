class DbgModel2TargetObjectImpl:
    def __init__(self, model, parent, name, type_hint):
        self.model = model
        self.parent = parent
        self.name = name
        self.type_hint = type_hint

    @property
    def focus(self):
        return self._focus

    @focus.setter
    def focus(self, value):
        self._focus = value

    @property
    def accessible(self):
        return self._accessible

    @accessible.setter
    def accessible(self, value):
        self._accessible = value

    @property
    def model_object(self):
        return self._model_object

    @model_object.setter
    def model_object(self, value):
        self._model_object = value

    @property
    def intrinsics(self):
        return self._intrinsics

    @intrinsics.setter
    def intrinsics(self, value):
        self._intrinsics = value

    @property
    def bpt_id(self):
        return self._bpt_id

    @bpt_id.setter
    def bpt_id(self, value):
        self._bpt_id = value

    @staticmethod
    def index_object(obj):
        return obj.search_key()

    @staticmethod
    def key_object(obj):
        return PathUtils.make_key(index_object(obj))

    @staticmethod
    def get_hint_for_object(obj):
        type_kind = obj.type_kind()
        if type_kind is None:
            return ""
        else:
            return str(type_kind)

    async def request_native_elements(self):
        manager2 = self.manager()
        path_x = PathUtils.extend(["Debugger"], self.path)
        return await manager2.list_elements(path_x, self)

    async def request_native_attributes(self):
        manager2 = self.manager()
        path_x = PathUtils.extend(["Debugger"], self.path)
        return await manager2.list_attributes(path_x, self)

    async def request_augmented_attributes(self):
        return await self.request_attributes(False)

    async def request_elements(self, refresh=False):
        nlist = []
        rlist = []
        result = (await self.request_native_elements()).then(
            lambda list: (
                for entry in self.elements().entry_set():
                    if not list.contains(entry.get_value()):
                        if isinstance(entry.get_value(), DbgStateListener):
                            await manager2.remove_state_listener((DbgStateListener) entry.get_value())
                        elif isinstance(entry.get_value(), DbgEventsListener):
                            await manager2.remove_events_listener((DbgEventsListener) entry.get_value())
                        rlist.add(entry.key)
                    nlist.extend(list)

                return AsyncUtils.NIL
            )
        ).then_accept(
            lambda: (
                self.change_elements(rlist, nlist, {}, "Refreshed")
            )
        )

    def is_really_valid(self):
        for p in [self] + list(reversed([p.get_parent()])):
            if not p.is_valid():
                return False
        return True

    async def request_attributes(self, refresh=False):
        nmap = {}
        rlist = []
        result = (await self.request_native_attributes()).then(
            lambda map: (
                for entry in self.attributes().entry_set():
                    attribute = entry.get_value()
                    if not map.contains(attribute):
                        if isinstance(attribute, DbgStateListener):
                            await manager2.remove_state_listener((DbgStateListener) attribute)
                        elif isinstance(attribute, DbgEventsListener):
                            await manager2.remove_events_listener((DbgEventsListener) attribute)
                        rlist.add(entry.key)

                nmap.update(map)
            )
        ).then_accept(
            lambda: (
                if not self.is_really_valid():
                    return
                for key in ["key", "type_hint"]:
                    value = getattr(self.model_object, key)
                    attrs[key] = value

                change_attributes(nlist, nmap, "Refreshed")
            )
        )

    async def add_model_object_attributes(self):
        if self.model_object is None or not self.is_really_valid():
            return CompletableFuture.completed_future(None)

        key = self.model_object.search_key()
        kind = self.model_object.get_kind()
        tk = self.model_object.type_kind()

        attrs["display_attribute_name"] = key
        if kind is not None:
            attrs["kind_attribute_name"] = str(kind)
        if tk is not None:
            attrs["type_attribute_name"] = str(tk)

    async def process_model_object_elements(self, list):
        futures = [process_element(to) for to in list]
        all_of = await CompletableFuture.all(futures)
        return all_of

    async def process_element(self, target_object):
        if isinstance(target_object, DbgModelTargetObject):
            proxy = (DbgModelTargetProxy) target_object
            if isinstance(proxy, TargetStackFrame) or \
               isinstance(proxy, TargetModule) or \
               isinstance(proxy, TargetBreakpointSpec):
                return await delegate.request_attributes(False)

    async def fetch_child(self, key):
        for elem in self.elements().values():
            if PathUtils.is_link(self.path, key, elem.get_path()):
                continue
            else:
                return CompletableFuture.completed_future(elem)
