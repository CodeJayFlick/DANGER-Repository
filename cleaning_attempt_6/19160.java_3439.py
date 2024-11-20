class MaterialRegistry:
    def __init__(self):
        self.materials = list(Material.values())

    @staticmethod
    def load(names):
        materials = list(Material)
        mappings = []
        
        for i, name in enumerate(names):
            if not name:  # This slot is intentionally empty
                continue
            
            mat = Material.get_material(name) or Material.get_material(name, True)
            
            if mat:
                mappings.append(mat)
                
        for material in materials:
            if material not in mappings:
                mappings.append(material)

        return MaterialRegistry([mappings])

    def get_material(self, id):
        try:
            return self.materials[id]
        except IndexError:
            raise ValueError("Invalid material ID")

    def get_id(self, material):
        try:
            return self.materials.index(material)
        except ValueError:
            raise AssertionError("Material registry out-of-date")

    def get_materials(self):
        return self.materials


class MaterialRegistryOld(MaterialRegistry):
    newMaterials = Skript.is_running_minecraft(1, 13)

    @staticmethod
    def load(names):
        materials = list(Material)
        mappings = []
        
        for i, name in enumerate(names):
            if not name:  # This slot is intentionally empty
                continue
            
            mat = Material.get_material(name) or Material.valueOf(name)
            
            if mat:
                mappings.append(mat)
                
        for material in materials:
            if material not in mappings:
                mappings.append(material)

        return MaterialRegistryOld([mappings])
