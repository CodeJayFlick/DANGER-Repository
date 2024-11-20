class HelpModuleCollection:
    def __init__(self):
        self.help_locations = set()
        self.input_help = None
        self.external_help_sets = []
        self.path_to_help_file_map = {}

    @staticmethod
    def from_help_directory(dir):
        return HelpModuleCollection([dir])

    @staticmethod
    def from_files(files):
        return HelpModuleCollection(list(map(lambda file: HelpBuildUtils.to_location(file), files)))

    @staticmethod
    def from_help_locations(locations):
        return HelpModuleCollection(locations)

    def load_tocs(self):
        for location in self.help_locations:
            if not location.is_help_input_source():
                continue

            if self.input_help is not None:
                raise ValueError("Cannot have more than one source input help module. Found a second input module: " + str(location))

            self.input_help = location

    def load_help_sets(self):
        for location in self.help_locations:
            if location.is_help_input_source():
                continue

            help_set = location.get_help_set()
            self.external_help_sets.append(help_set)

    @property
    def contains_help_files(self):
        return any(location.contains_help() for location in self.help_locations)

    @property
    def get_help_roots(self):
        return [location.get_help_location() for location in self.help_locations]

    def get_duplicate_anchors_by_file(self):
        result = {}
        for location in self.help_locations:
            anchors = location.get_duplicate_anchors_by_file()
            if anchors is not None:
                result.update(anchors)

        return result

    def get_duplicate_anchors_by_topic(self):
        result = {}
        for location in self.help_locations:
            anchors = location.get_duplicate_anchors_by_topic()
            if anchors is not None:
                result.update(anchors)

        return result

    @property
    def all_hrefs(self):
        return [href for location in self.help_locations for href in location.all_hrefs()]

    @property
    def all_imgs(self):
        return [img for location in self.help_locations for img in location.all_imgs()]

    @property
    def all_anchor_definitions(self):
        return [anchor_definition for location in self.help_locations for anchor_definition in location.all_anchor_definitions()]

    def get_anchor_definition(self, target):
        if not isinstance(target, Path):
            raise ValueError("Target must be a Path")

        map = self.path_to_help_file_map
        help_file = map.get(PathKey(target))
        if help_file is None:
            return None

        definition = help_file.anchor_definitions.get(target)
        return definition

    def get_help_file(self, path):
        if not isinstance(path, Path):
            raise ValueError("Path must be a Path")

        map = self.path_to_help_file_map
        return map.get(PathKey(path))

    @property
    def toc_definitions_by_id(self):
        result = {}
        for location in self.help_locations:
            definitions = location.toc_definitions_by_id()
            if definitions is not None:
                result.update(definitions)

        return result

    @property
    def external_toc_items_by_id(self):
        map = {}
        for help_set in self.external_help_sets:
            view = TOCView(help_set.get_navigator_view("TOC"))
            node = view.data_as_tree()
            url = help_set.get_help_set_url()

            try:
                data_url = URL(url, str(view.parameters["data"]))
                path = Path(data_url.to_uri())
                self.add_prebuilt_item(node, path, map)
            except (MalformedURLException, URISyntaxException) as e:
                raise RuntimeError("Internal error", e)

        return map

    def add_prebuilt_item(self, node, toc_path, map_by_display):
        user_object = node.user_object
        item = CustomTreeItemDecorator(user_object)
        if item is not None:
            parent_node = node.parent
            parent_item = None
            if parent_node is not None:
                dec = CustomTreeItemDecorator(parent_node.user_object)
                if dec is not None:
                    parent_item = map_by_display.get(dec.toc_id)

            target_id = item.id
            display_text = item.display_text
            toc_id = item.toc_id
            target = target_id.id_string if target_id else None

            external = TOCItemExternal(parent_item, toc_path, toc_id, display_text, target, item.name, -1)
            map_by_display[toc_id] = external

        children = node.children()
        while children.has_more_elements():
            child_node = next(children)
            self.add_prebuilt_item(child_node, toc_path, map_by_display)

    @property
    def input_toc_items(self):
        return [item for location in self.help_locations if isinstance(location, HelpModuleLocation) and location.is_help_input_source() for item in location.toc_items()]

    @property
    def toc_hrefs(self):
        definitions = []
        for file in self.external_help_sets:
            view = TOCView(file.get_navigator_view("TOC"))
            node = view.data_as_tree()
            children = node.children()

            while children.has_more_elements():
                child_node = next(children)
                try:
                    target_attribute = child_node.user_object.target_attribute
                    definitions.append(HREF(self.input_help, file.file(), target_attribute, 0))
                except (URISyntaxException) as e:
                    raise RuntimeError("Malformed reference: ", e)

        return definitions

class PathKey:
    def __init__(self, path):
        if not isinstance(path, Path):
            raise ValueError("Path must be a Path")

        self.path = str(path).replace('\\', '/')

    @property
    def hash(self):
        return self.path.hash()

    @property
    def equals(self, obj):
        if self is obj:
            return True

        if not isinstance(obj, PathKey):
            return False

        other = obj
        return self.path == other.path

    @property
    def to_string(self):
        return str(self.path)
