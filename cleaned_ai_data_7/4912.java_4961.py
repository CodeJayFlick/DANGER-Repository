class ObjectiveC2Constants:
    OBJC2_PREFIX = "__objc_"
    
    OBJC2_CATEGORY_LIST = f"{OBJC2_PREFIX}catlist"
    OBJC2_CLASS_LIST = f"{OBJC2_PREFIX}classlist"
    OBJC2_CLASS_REFS = f"{OBJC2_PREFIX}classrefs"
    OBJC2_CONSTANTS = f"{OBJC2_PREFIX}const"
    OBJC2_DATA = f"{OBJC2_PREFIX}data"
    OBJC2_IMAGE_INFO = f"{OBJC2_PREFIX}imageinfo"
    OBJC2_MESSAGE_REFS = f"{OBJC2_PREFIX}msgrefs"
    OBJC2_NON_LAZY_CLASS_LIST = f"{OBJC2_PREFIX}nlclslist"
    OBJC2_PROTOCOL_LIST = f"{OBJC2_PREFIX}protolist"
    OBJC2_PROTOCOL_REFS = f"{OBJC2_PREFIX}protorefs"
    OBJC2_SELECTOR_REFS = f"{OBJC2_PREFIX}selrefs"
    OBJC2_SUPER_REFS = f"{OBJC2_PREFIX}superrefs"

    def get_objective_c2_section_names(self):
        section_names = []
        for field_name in dir(ObjectiveC2Constants):
            if not field_name.startswith(OBJC2_PREFIX) or field_name == "OBJC2_PREFIX":
                continue
            section_names.append(field_name)
        return section_names

    @staticmethod
    def is_objective_c2(program):
        format = program.get_executable_format()
        if format.lower() == "macho":
            blocks = program.get_memory().get_blocks()
            for block in blocks:
                if block.name.startswith(OBJC2_PREFIX):
                    return True
        return False

NAMESPACE = "objc2"
CATEGORY = "/_objc2_"

category_path = CategoryPath(CATEGORY)
