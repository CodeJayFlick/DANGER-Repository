class CompositeVerticalLayoutTextFieldTest:
    LONG_STRING = "Supercalifragilisticexpialidocious"
    
    def setUp(self):
        self.font_metrics = None
        self.field = None
    
    def create_field(self, line_limit, lines):
        rows = lines
        font_metrics = get_font_metrics("Times New Roman", 14)
        
        field = CompositeVerticalLayoutTextField(max_lines=line_limit, fields=[], startX=100, width=100, hl_factory=lambda x: [])
        
        for row in range(len(rows)):
            elements = [create_row(row, text, Color.BLUE) for text in rows[row].split()]
            for element in elements:
                field.add_field(element)
        
        return field
    
    def create_row(self, row, text, color):
        return TextFieldElement(AttributedString(text, color, font_metrics), row, 0)

    @staticmethod
    def get_font_metrics(font_name, size):
        # This is a placeholder for the actual method to calculate font metrics.
        pass

    @classmethod
    def setUpClass(cls):
        cls.font_metrics = None
    
    def test_screen_to_data_location(self):
        assert_row_col(0, 0, self.field.screen_to_data_location(0, 0))
        # ... rest of the tests for screen_to_data_location
        
    def test_text_offset_to_screen_location(self):
        # ... rest of the tests for text_offset_to_screen_location

    @classmethod
    def tearDownClass(cls):
        cls.font_metrics = None
    
    if __name__ == '__main__':
        unittest.main()
