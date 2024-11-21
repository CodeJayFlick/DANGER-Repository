class AnchorManager:
    def __init__(self):
        self.anchors_by_help_path = {}
        self.anchors_by_id = {}
        self.anchors_by_name = {}
        self.duplicate_anchors_by_id = {}

        self.anchor_refs = []
        self.img_refs = []

    def add_anchor(self, file, anchor_name, src_line_no):
        anchor_definition = AnchorDefinition(file, anchor_name, src_line_no)

        id = anchor_definition.get_id()
        if id in self.anchors_by_id:
            self.add_duplicate_anchor(anchor_name, anchor_definition, id)
            return

        self.anchors_by_id[id] = anchor_definition
        self.anchors_by_help_path[anchor_definition.get_help_path()] = anchor_definition

        if anchor_name is not None:
            self.anchors_by_name[anchor_name] = anchor_definition

    def add_duplicate_anchor(self, anchor_name, anchor_definition, id):
        list_ = self.duplicate_anchors_by_id.get(id)
        if list_ is None:
            list_ = [self.anchors_by_id[id]]
            self.duplicate_anchors_by_id[id] = list_
        else:
            list_.append(anchor_definition)

        # special code: make sure at least one of these duplicates makes it into the map
        if anchor_name is None:
            return

        if not (anchor_name in self.anchors_by_name):
            self.anchors_by_name[anchor_name] = anchor_definition
            self.anchors_by_help_path[anchor_definition.get_help_path()] = anchor_definition

    def get_anchors_by_help_path(self):
        return self.anchors_by_help_path

    def get_anchor_for_help_path(self, path):
        if path is None:
            return None
        return self.anchors_by_help_path.get(path)

    def add_anchor_ref(self, href):
        self.anchor_refs.append(href)

    def add_image_ref(self, ref):
        self.img_refs.append(ref)

    def get_anchor_refs(self):
        return self.anchor_refs

    def get_image_refs(self):
        return self.img_refs

    def get_anchor_for_name(self, anchor_name):
        return self.anchors_by_name.get(anchor_name)

    def get_duplicate_anchors_by_id(self):
        self.cleanup_duplicate_anchors()
        return self.duplicate_anchors_by_id

    def cleanup_duplicate_anchors(self):
        for id in list(self.duplicate_anchors_by_id.keys()):
            list_ = self.duplicate_anchors_by_id[id]
            for anchor_definition in list(list_, ):
                if anchor_definition.get_line_number() < 0:
                    list_.remove(anchor_definition)

            if len(list_) == 1:
                del self.duplicate_anchors_by_id[id]

class AnchorDefinition:
    def __init__(self, file, name, line_no):
        self.file = file
        self.name = name
        self.line_number = line_no

    def get_id(self):
        return f"{self.file}:{self.name}:{self.line_number}"

    def get_help_path(self):
        # implementation of get_help_path()
        pass

class HREF:
    pass

class IMG:
    pass
