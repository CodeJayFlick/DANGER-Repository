Here is the translation of the Java code into Python:

```Python
class SimpleLanguageTranslator:
    def __init__(self, translator_spec_source, old_language_id, old_version, new_language_id, new_version):
        self.translator_spec_source = translator_spec_source
        self.old_language_id = old_language_id
        self.old_version = old_version
        self.new_language_id = new_language_id
        self.new_version = new_version

    def is_valid(self):
        if not super().is_valid():
            return False
        
        if len(self.space_name_map) == 0:
            try:
                validate_default_space_map()
            except IncompatibleLanguageException as e:
                log.error("Bad translation spec ({}) : {}".format(e.message, self))
                return False
        else:
            old_spaces = set(old_factory.get_physical_spaces())
            for name in self.space_name_map.keys():
                space = old_factory.get_address_space(name)
                if space is None:
                    err_buf.append(f" Mapped address space not found (from): {name}\r\n")
                    continue
                
                new_name = self.space_name_map[name]
                if new_name is None:
                    if old_spaces.remove(space):
                        err_buf.append(" Default space must be mapped: " + name + "\r\n")
                    else:
                        continue
                new_space = new_factory.get_address_space(new_name)
                if new_space is None:
                    err_buf.append(f" Mapped address space not found (to): {name}\r\n")
                    continue
                
            if len(old_spaces) > 0:
                err_buf.append(" Failed to map old address spaces: ")
                for space in old_spaces:
                    err_buf.append(space.name + " ")
                
        return True

    def get_new_address_space(self, old_space_name):
        if not self.is_valid():
            raise IllegalStateException("Translator has not been validated")
        
        if len(self.space_name_map) == 0:
            return super().get_new_address_space(old_space_name)
        else:
            new_name = self.space_name_map.get(old_space_name)
            if new_name is None:
                return None
            return new_factory.get_address_space(new_name)

    def get_new_register_value(self, old_register_value):
        old_reg = old_register_value.register
        if not (self.clear_all_context or context_settings is None) and old_reg.is_base_register() and old_reg.is_processor_context():
            return True
        
        return super().get_new_register_value(old_register_value)

    def get_new_compiler_spec_id(self, compiler_spec_id):
        old_spec_id = compiler_spec_id.id_as_string
        new_spec_id = self.compiler_spec_map.get(old_spec_id)
        if new_spec_id is not None:
            return CompilerSpecID(new_spec_id)
        
        return super().get_new_compiler_spec_id(compiler_spec_id)

    def get_new_register(self, old_reg):
        if self.register_name_map is not None:
            new_name = self.register_name_map.get(old_reg.name)
            if new_name is not None:
                return new_factory.get_register(new_name)
        
        return super().get_new_register(old_reg)

    @staticmethod
    def get_simple_language_translator(translator_spec_source, language_translation_element):
        from_language_id = None
        to_language_id = None
        from_version = -1
        to_version = -1
        
        space_map = {}
        register_map = {}
        context_settings = {}
        compiler_spec_map = {}
        clear_all_context = False
        post_upgrade_instruction_handler_class = None
        
        new_spaces_mapped = set()
        
        for element in language_translation_element.children:
            if "from_language" == element.name:
                from_version = int(element.get_attribute_value("version"))
                from_language_id = LanguageID(get_language_id(element.text))
            
            elif "to_language" == element.name:
                to_version = int(element.get_attribute_value("version"))
                to_language_id = LanguageID(get_language_id(element.text))
            
            elif "map_space" == element.name:
                parse_map_entry(element, space_map, new_spaces_mapped)
            
            elif "delete_space" == element.name:
                parse_delete_entry(element, space_map)
            
            elif "map_register" == element.name:
                parse_map_entry(element, register_map, None)
            
            elif "set_context" == element.name:
                parse_set_context(element, context_settings)
            
            elif "clear_all_context" == element.name:
                clear_all_context = True
            
            elif "map_compiler_spec" == element.name:
                parse_map_entry(element, compiler_spec_map, None)
            
            elif "post_upgrade_handler" == element.name:
                if post_upgrade_instruction_handler_class is not None:
                    raise SAXException("Only a single post_upgrade_analzer may be specified")
                
                post_upgrade_instruction_handler_class = parse_post_upgrade_handler_entry(element)
        
        if from_language_id is None or from_language_id.id_as_string.strip() == "":
            raise SAXException("Missing valid 'from_language' element")
        
        if to_language_id is None or to_language_id.id_as_string.strip() == "":
            raise SAXException("Missing valid 'to_language' element")
        
        if from_language_id.equals(to_language_id) and from_version >= to_version:
            raise SAXException(f"Invalid language translator versions: {from_version} -> {to_version}")
        
        return SimpleLanguageTranslator(translator_spec_source, from_language_id, from_version, to_language_id, to_version)

    @staticmethod
    def get_post_upgrade_handler_entry(element):
        class_name = element.get_attribute_value("class")
        if class_name is None:
            raise SAXException(f"{element.name} must specify 'class' attribute")

        try:
            clazz = Class.forName(class_name)
            post_upgrade_instruction_handler_class = (clazz.as_subclass(LanguagePostUpgradeInstructionHandler))
            return post_upgrade_instruction_handler_class
        except Exception as e:
            if isinstance(e, SAXException):
                raise e
            else:
                raise SAXException(f"Failed to instantiate: {class_name}", e)

    @staticmethod
    def parse_map_entry(element, name_map, duplicate_check_set=None):
        from_name = element.get_attribute_value("from")
        to_name = element.get_attribute_value("to")

        if from_name is None or to_name is None:
            raise SAXException(f"{element.name} must include both 'from' and 'to' attributes")

        if duplicate_check_set is not None:
            if duplicate_check_set.contains(to_name):
                raise SAXException(f"{element.name} may not map the same name more than once: {to_name}")
            
            duplicate_check_set.add(to_name)
        
        if name_map.containsKey(from_name):
            raise SAXException(f"{element.name} may not map the same name more than once: {from_name}")

        name_map.put(from_name, to_name)

    @staticmethod
    def parse_delete_entry(element, name_map):
        name = element.get_attribute_value("name")

        if name is None:
            raise SAXException(f"{element.name} must include 'name' attribute")
        
        if not name_map.containsKey(name):
            return
        
        name_map.put(name, None)

    @staticmethod
    def parse_set_context(element, context_settings):
        name = element.get_attribute_value("name")

        if name is None:
            raise SAXException(f"{element.name} must include 'name' attribute")
        
        val_str = element.get_attribute_value("value")

        if val_str is None:
            raise SAXException(f"Missing required set_context 'value' attribute")

        try:
            if val_str.startswith("0x"):
                val_str = val_str[2:]
                val = BigInteger(val_str, 16)
            else:
                val = BigInteger(val_str)

        except NumberFormatException as e:
            raise SAXException(f"invalid set_context attribute value: {name}=\"{val_str}\"")

        context_settings.put(name, val)