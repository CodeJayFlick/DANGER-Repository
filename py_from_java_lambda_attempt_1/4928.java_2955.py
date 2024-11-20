Here is the translation of the given Java code into equivalent Python:

```Python
class ObjectiveC1Constants:
    NAMESPACE = "objc"
    CATEGORY = "/objc"
    CATEGORY_PATH = CategoryPath(CATEGORY)

    SECTION_FIELD_NAME_PREFIX = "OBJC_SECTION_"

    OBJC_SECTION_CATEGORY = "__category"
    OBJC_SECTION_CATEGORY_CLASS_METHODS = "__cat_cls_meth"
    OBJC_SECTION_CATEGORY_INSTANCE_METHODS = "__cat_inst_meth"
    OBJC_SECTION_CLASS = "__class"
    OBJC_SECTION_CLASS_METHODS = "__cls_meth"
    OBJC_SECTION_CLASS_REFS = "__cls_refs"
    OBJC_SECTION_INSTANCE_METHODS = "__inst_meth"
    OBJC_SECTION_INSTANCE_VARS = "__instance_vars"
    OBJC_SECTION_MESSAGE_REFS = "__message_refs"
    OBJC_SECTION_METACLASS = "__meta_class"
    OBJC_SECTION_MODULE_INFO = "__module_info"
    OBJC_SECTION_PROTOCOL = "__protocol"
    OBJC_SECTION_SYMBOLS = "__symbols"
    OBJC_SECTION_DATA = "__data"

    def get_objective_c_section_names(self):
        section_names = []
        for field_name in dir(ObjectiveC1Constants):
            if field_name.startswith(SECTION_FIELD_NAME_PREFIX) and isinstance(getattr(ObjectiveC1Constants, field_name), str):
                section_names.append(getattr(ObjectiveC1Constants, field_name))
        return section_names

    READ_UNIX2003 = "_read$UNIX2003"
    OBJC_MSG_SEND = "_objc_msgSend"
    OBJC_MSG_SEND_WILDCARD = "_objc_msgSend*"
    OBJC_MSG_SEND_RTP_NAME = "_objc_msgSend_rtp"

    OBJ_MSGSEND_RTP = 0xfffeff00
    OBJ_MSGSEND_RTP_EXIT = 0xfffeff00 + 0x100

    @staticmethod
    def is_objective_c(program):
        if program.executable_format == "MACH-O":
            for section_name in ObjectiveC1Constants.get_objective_c_section_names():
                block = program.memory.block(section_name)
                if block:
                    return True
        return False


class CategoryPath(str): pass

class Program: pass
```

Please note that Python does not have direct equivalent of Java's `getDeclaredFields()` method. So, I used the built-in `dir()` function to get all attributes (methods and variables) in the class, then checked if each attribute is a string by using `isinstance()`.