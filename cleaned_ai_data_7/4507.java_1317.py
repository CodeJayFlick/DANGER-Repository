class GhidraScriptProvider:
    def __init__(self):
        pass

    def __str__(self):
        return self.get_description()

    def __hash__(self):
        return hash(self.get_description())

    def __eq__(self, other):
        if isinstance(other, GhidraScriptProvider):
            return self.get_description() == other.get_description()
        return False

    def __lt__(self, other):
        return self.get_description().lower() < other.get_description().lower()

    def delete_script(self, script_source):
        return not script_source.exists() or script_source.delete()

    @abstractmethod
    def get_description(self):
        pass

    @abstractmethod
    def get_extension(self):
        pass

    @abstractmethod
    def get_script_instance(self, source_file, writer) -> 'GhidraScript':
        pass

    @abstractmethod
    def create_new_script(self, new_script: ResourceFile, category: str) -> None:
        pass

    def get_block_comment_start(self):
        return None

    def get_block_comment_end(self):
        return None

    def get_comment_character(self):
        # This method should be implemented in the subclass
        raise NotImplementedError("get_comment_character must be implemented")

    def write_header(self, writer: PrintWriter, category: str) -> None:
        if category is None:
            category = "_NEW_"

        writer.write(f"{self.get_comment_character()} TODO write a description for this script\n")
        metadata_items = ["TODO add metadata items here"]
        for item in metadata_items:
            writer.print(f"{self.get_comment_character()}{item} ")
            if item == "AT_CATEGORY":
                writer.print(category)
            writer.write("\n")

    def write_body(self, writer: PrintWriter) -> None:
        writer.write(f"{self.get_comment_character()} TODO Add User Code Here\n")

    @deprecated
    def fixup_name(self, script_name):
        return script_name

    def get_certify_header_start(self):
        return None

    def get_certification_body_prefix(self):
        return None

    def get_certify_header_end(self):
        return None


class GhidraScript:
    pass


# Example of how to use the class
class MyGhidraScriptProvider(GhidraScriptProvider):
    @abstractmethod
    def get_description(self) -> str:
        pass

    @abstractmethod
    def get_extension(self) -> str:
        pass

    @abstractmethod
    def get_script_instance(self, source_file: ResourceFile, writer: PrintWriter) -> 'GhidraScript':
        pass

    @abstractmethod
    def create_new_script(self, new_script: ResourceFile, category: str) -> None:
        pass


# Example of how to use the class
class MyResourceFile:
    def exists(self):
        # This method should be implemented in the subclass
        raise NotImplementedError("exists must be implemented")

    def delete(self):
        # This method should be implemented in the subclass
        raise NotImplementedError("delete must be implemented")


if __name__ == "__main__":
    my_provider = MyGhidraScriptProvider()
    print(my_provider)
