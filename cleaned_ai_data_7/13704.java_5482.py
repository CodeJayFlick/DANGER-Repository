class AbstractFactoryTest:
    def __init__(self):
        self.app = App()

    def test_verify_king_creation(self):
        self.app.create_kingdom(Kingdom.FACTORY_MAKER.KINGDOM_TYPE.ELF)
        kingdom = self.app.get_kingdom()
        
        elf_king = kingdom.get_king()
        assert isinstance(elf_king, ElfKing), "Expected ElfKing"
        assert elf_king.getDescription() == ElfKing.DESCRIPTION
        
        self.app.create_kingdom(Kingdom.FACTORY_MAKER.KINGDOM_TYPE.ORC)
        orc_king = kingdom.get_king()
        assert isinstance(orc_king, OrcKing), "Expected OrcKing"
        assert orc_king.getDescription() == OrcKing.DESCRIPTION

    def test_verify_castle_creation(self):
        self.app.create_kingdom(Kingdom.FACTORY_MAKER.KINGDOM_TYPE.ELF)
        kingdom = self.app.get_kingdom()
        
        elf_castle = kingdom.get_castle()
        assert isinstance(elf_castle, ElfCastle), "Expected ElfCastle"
        assert elf_castle.getDescription() == ElfCastle.DESCRIPTION
        
        self.app.create_kingdom(Kingdom.FACTORY_MAKER.KINGDOM_TYPE.ORC)
        orc_castle = kingdom.get_castle()
        assert isinstance(orc_castle, OrcCastle), "Expected OrcCastle"
        assert orc_castle.getDescription() == OrcCastle.DESCRIPTION

    def test_verify_army_creation(self):
        self.app.create_kingdom(Kingdom.FACTORY_MAKER.KINGDOM_TYPE.ELF)
        kingdom = self.app.get_kingdom()
        
        elf_army = kingdom.get_army()
        assert isinstance(elf_army, ElfArmy), "Expected ElfArmy"
        assert elf_army.getDescription() == ElfArmy.DESCRIPTION
        
        self.app.create_kingdom(Kingdom.FACTORY_MAKER.KINGDOM_TYPE.ORC)
        orc_army = kingdom.get_army()
        assert isinstance(orc_army, OrcArmy), "Expected OrcArmy"
        assert orc_army.getDescription() == OrcArmy.DESCRIPTION

    def test_verify_elf_kingdom_creation(self):
        self.app.create_kingdom(Kingdom.FACTORY_MAKER.KINGDOM_TYPE.ELF)
        kingdom = self.app.get_kingdom()
        
        king = kingdom.get_king()
        assert isinstance(king, ElfKing), "Expected ElfKing"
        assert king.getDescription() == ElfKing.DESCRIPTION
        castle = kingdom.get_castle()
        assert isinstance(castle, ElfCastle), "Expected ElfCastle"
        assert castle.getDescription() == ElfCastle.DESCRIPTION
        army = kingdom.get_army()
        assert isinstance(army, ElfArmy), "Expected ElfArmy"
        assert army.getDescription() == ElfArmy.DESCRIPTION

    def test_verify_orc_kingdom_creation(self):
        self.app.create_kingdom(Kingdom.FACTORY_MAKER.KINGDOM_TYPE.ORC)
        kingdom = self.app.get_kingdom()
        
        king = kingdom.get_king()
        assert isinstance(king, OrcKing), "Expected OrcKing"
        assert king.getDescription() == OrcKing.DESCRIPTION
        castle = kingdom.get_castle()
        assert isinstance(castle, OrcCastle), "Expected OrcCastle"
        assert castle.getDescription() == OrcCastle.DESCRIPTION
        army = kingdom.get_army()
        assert isinstance(army, OrcArmy), "Expected OrcArmy"
        assert army.getDescription() == OrcArmy.DESCRIPTION

if __name__ == "__main__":
    test_case = AbstractFactoryTest()
    unittest.main(test=AbstractFactoryTest)
