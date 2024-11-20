import os
from ghidra.app.script import GhidraScript
from ghidra.framework.data import GhidraFileData
from ghidra.program.model.lang import LanguageDescription
from ghidra.util.exception import CancelledException

class FixLangId(GhidraScript):
    LANGUAGE_ID = "Language ID"
    LANGUAGE_VERSION = "Language Version"
    TABLE_NAME = "Program"

    def run(self) -> None:
        df = self.ask_program_file("Select Program File")
        if df is None:
            return
        if df.is_versioned():
            Msg.show_error(None, None, "Script Error", 
                            "Selected project file must not be under version control!")
            return

        gf = GhidraFileData(df)
        
        method = type(GhidraFile).get_method("getFileData")
        file_data = method.invoke(gf)

        item = self.get_instance_field("folderItem", file_data)
        if isinstance(item, LocalDatabaseItem):
            bf = item.open_for_update(-1)
            dbh = DBHandle(bf)
            if not self.modify_language(df, dbh):
                return
            dbh.save("Set Language", None, TaskMonitorAdapter.DUMMY_MONITOR)
            dbh.close()
        else:
            Msg.show_error(None, None, "Script Error", 
                            "Unsupported file type!")
            return

    def modify_language(self, df: DomainFile, dbh: DBHandle) -> bool:
        # TODO: Check for address map and overlay entries which could break from
        # changing the memory model !!

        table = dbh.get_table(TABLE_NAME)
        if table is None:
            Msg.show_error(None, None, "Script Error", 
                            "Bad program database!!")
            return False

        record = table.get_record(StringField(LANGUAGE_ID))
        if record is None:  
            # must be in old style combined language/compiler spec format
            Msg.show_error(None, None, "Script Error", 
                            "Old program file!  Language fix is not appropriate.")
            return False
        
        lang_id = record.get_string(0)
        desc = DefaultLanguageService().get_language_description(new LanguageID(lang_id))
        
        try:
            new_lang_id = self.ask_choice("Select New Language", "Language ID:", [desc.get_language_id()], None)
            if new_lang_id is not None:
                Msg.warn(self, f"Changing language ID from '{record.get_string(0)}' to '{new_lang_id}' for program: {df.name}")
                record.set_string(0, new_lang_id)
                table.put_record(record)
                record = table.create_record(StringField(LANGUAGE_VERSION))
                record.set_string(0, desc.get_version() + "." + desc.get_minor_version())
                table.put_record(record)
            return True
        except CancelledException:
            pass
        
    def ask_program_file(self, title: str) -> DomainFile:
        domain_files = []
        
        dtd = DataTreeDialog(None, title, DataTreeDialog.OPEN)
        dtd.add_ok_action_listener(lambda e: 
                                    dtd.close() and (domain_files[0] := dtd.get_domain_file()))
        
        try:
            SwingUtilities.invoke_and_wait(dtd.show_component())
        except Exception as e:
            return None
        
        if domain_files[0]:
            if not isinstance(domain_files[0].get_domain_object_class(), Program):
                Msg.show_error(None, None, "Script Error", 
                                "Selected project file is not a program file!")
                return None
            return domain_files[0]
        
    def get_instance_field(self, field_name: str, owner_instance) -> object:
        if owner_instance is None:
            raise NullPointerException("Owner of instance field cannot be null")
        
        try:
            # Get the field from the class object 
            field = type(owner_instance).get_declared_field(field_name)
            
            # Open up the field so that we have access
            field.set_accessible(True)
            
            # Get the field from the object instance that we were provided
            return field.get(owner_instance)
        except Exception as e:
            raise RuntimeError(f"Unable to use reflection to obtain {field_name} from class: {type(owner_instance)}", e)

    def locate_field_object_on_class(self, field_name: str, containing_class) -> Field:
        try:
            # Get the declared field
            return type(containing_class).get_declared_field(field_name)
        except NoSuchFieldException as nsfe:
            parent_class = containing_class.get_superclass()
            
            if parent_class is not None:
                return self.locate_field_object_on_class(field_name, parent_class)

    def ask_choice(self, title: str, prompt: str, choices: list[str], default=None) -> str | None:
        try:
            choice = input(f"{title}\n{prompt} ({', '.join(choices)}) [{default or ''}] ")
            return choice if choice else default
        except Exception as e:
            return None

    def run_script(self):
        self.run()
