Here is a translation of your Java code into equivalent Python:

```Python
class GroupedFunctionGraphComponentPanel:
    def __init__(self, controller, vertex, group_vertex_user_text):
        super().__init__()
        self.group_vertex = vertex
        self.user_text = group_vertex_user_text
        self.title = self.create_title()
        
        options = controller.get_function_graph_options()
        default_background_color = options.get_default_group_background_color()

        layout = BorderLayout()
        set_layout(layout)

        generic_header = GenericHeader()
        generic_header.set_component(self)
        generic_header.set_title(self.title)

        content_panel = JPanel()
        content_panel.set_border(BorderFactory.create_empty_border(5, 5, 5, 5))
        content_panel.set_layout(VerticalLayout())
        content_panel.set_opaque(True)
        content_panel.set_background(default_background_color)

        user_text_area = JTextArea()
        user_text_area.set_opaque(True)
        user_text_area.set_background(default_background_color)
        user_text_area.set_editable(False)
        user_text_area.set_line_wrap(True)
        user_text_area.set_wrap_style_word(True)
        user_text_area.set_border(BorderFactory.create_empty_border())

        content_panel.add(user_text_area)

        set_opaque(True)
        set_background(default_background_color)

        add(generic_header, BorderLayout.NORTH)
        add(content_panel, BorderLayout.CENTER)

        beveled_border = BevelBorder(RAISED,
            Color(225, 225, 225), Color(155, 155, 155),
            Color(96, 96, 96), Color(0, 0, 0))
        set_border(beveled_border)

        self.create_actions()
        self.set_user_text(self.user_text)
        
    def create_title(self):
        vertices = self.group_vertex.get_vertices()
        size = len(vertices)
        min_address = None
        max_address = None

        for vertex in vertices:
            addresses = vertex.get_addresses()
            if min_address is None or addresses.min() < min_address:
                min_address = addresses.min()

            if max_address is None or addresses.max() > max_address:
                max_address = addresses.max()

        return f"Grouped Vertex - {size} vertices [{min_address} - {max_address}]"

    def create_actions(self):
        first_group = "group1"
        second_group = "group2"

        group_action = DockingAction("Group Vertices", FunctionGraphPlugin.class.getName())
        group_action.set_description("Combine selected vertices into one vertex")
        image_icon = ResourceManager.load_image("images/shape_handles.png")
        group_action.set_toolbar_data(ToolBarData(image_icon, second_group))
        group_action.set_help_location(HelpLocation(FunctionGraphPlugin.class.getName(), "Group_Vertex_Action_Group"))

        regroup_action = DockingAction("Regroup Vertices", FunctionGraphPlugin.class.getName())
        regroup_action.set_description("Restore vertex and siblings back to group form")
        image_icon = ResourceManager.load_image("images/edit-redo.png")
        regroup_action.set_toolbar_data(ToolBarData(image_icon, second_group))
        regroup_action.set_help_location(HelpLocation(FunctionGraphPlugin.class.getName(), "Vertex_Action_Regroup"))

        ungroup_action = DockingAction("Ungroup Vertices", FunctionGraphPlugin.class.getName())
        ungroup_action.set_description("Ungroup selected vertices into individual vertex")
        image_icon = ResourceManager.load_image("images/shape_ungroup.png")
        ungroup_action.set_toolbar_data(ToolBarData(image_icon, second_group))
        ungroup_action.set_help_location(HelpLocation(FunctionGraphPlugin.class.getName(), "Vertex_Action_Ungroup"))

        add_to_group_action = DockingAction("Add to Group", FunctionGraphPlugin.class.getName())
        add_to_group_action.set_description("Add the selected vertices to this group")
        image_icon = ResourceManager.load_image("images/shape_square_add.png")
        add_to_group_action.set_toolbar_data(ToolBarData(image_icon, second_group))
        add_to_group_action.set_help_location(HelpLocation(FunctionGraphPlugin.class.getName(), "Vertex_Action_Group_Add"))

        set_vertex_most_recent_action = SetVertexMostRecentColorAction(controller, vertex)
        set_vertex_most_recent_action.set_help_location(HelpLocation(FunctionGraphPlugin.class.getName(), "Group_Vertex_Action_Color"))
        icon = set_vertex_most_recent_action.get_toolbar_icon()
        set_vertex_most_recent_action.set_toolbar_data(ToolBarData(icon, first_group))

        generic_header.add_action(set_vertex_most_recent_action)
        generic_header.add_action(ungroup_action)
        generic_header.add_action(add_to_group_action)
        generic_header.add_action(group_action)

    def update_text_area_size(self):
        format_manager = self.get_controller().get_minimal_format_manager()
        max_width = format_manager.get_max_width()

        if max_width <= 0:
            return

        user_text_area.set_size(max_width, int.MAX_VALUE)

    def set_user_text(self, text):
        old_text = self.user_text
        new_text = controller.prompt_user_for_group_vertex_text(None, self.user_text, self.group_vertex.get_vertices())

        if new_text is None or new_text == old_text:
            return

        self.user_text = new_text
        user_text_area.set_text(new_text)

        update_text_area_size()

    def get_user_text(self):
        return self.user_text

    # ... rest of the methods ...
```

Please note that this translation may not be perfect, as Python and Java have different syntaxes.