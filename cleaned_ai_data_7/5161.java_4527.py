import xml.etree.ElementTree as ET
from collections import defaultdict


class RichProductIdLoader:
    def load_product_id_store(self):
        product_id_store = {}
        
        try:
            built_in_file_path = Application.get_module_data_file("ms_pe_rich_products.xml")
            
            if built_in_file_path is not None:
                self.load_xml_file(built_in_file_path, product_id_store)
                
            user_settings_directory = Application.get_user_settings_directory()
            user_file_path = f"{user_settings_directory.parent}/rich_ids.xml"
            
            resource_file = ResourceFile(user_file_path)
            
            if resource_file.exists():
                self.load_xml_file(resource_file.path, product_id_store)
        except FileNotFoundError:
            pass
        
        return product_id_store

    def resolve_product_type(self, tool_description):
        description = tool_description.lower()
        
        if "import" in description or tool_description == "IMP":
            return MSProductType.Import
        elif "export" in description or tool_description == "EXP":
            return MSProductType.Export
        elif "imp/exp" in description:
            return MSProductType.ImportExport
        elif "linker" in description or tool_description == "LNK":
            return MSProductType.Linker
        elif "masm" in description or tool_description == "ASM":
            return MSProductType.Assembler
        elif "cvtres" in description or tool_description == "RES":
            return MSProductType.CVTRes
        elif "c++ compiler" in description:
            return MSProductType.CXX_Compiler
        elif "c compiler" in description:
            return MSProductType.C_Compiler
        
        if tool_description == "C++":
            return MSProductType.CXX_Compiler
        elif tool_description == "C":
            return MSProductType.C_ Compiler

        return MSProductType.Unknown


    def load_xml_file(self, file_path, product_id_store):
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for child in root:
                if child.tag == "product":
                    product = self.load_rich_product(child)
                    
                    if product is not None:
                        product_id_store[hex(product.compid.value)] = product
        except Exception as e:
            print(f"Error loading XML file: {e}")


    def load_rich_product(self, element):
        prodid_str = element.get("prodid")
        tool = element.get("tool")
        name = element.get("name")

        id = int(prodid_str, 16)

        type = self.resolve_product_type(tool)
        
        return RichProduct(id, name, type)


class XMLErrorHandler:
    def error(self, exception):
        raise SAXException(f"Error: {exception}")

    def fatalError(self, exception):
        raise SAXException(f"Fatal error: {exception}")

    def warning(self, exception):
        raise SAXException(f"Warning: {exception}")
