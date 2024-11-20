class SvgViewManager:
    REACT_CLASS = "RNSVGSvgView"
    m_tag_to_svg_view = {}
    m_tag_to_runnable = {}

    @staticmethod
    def set_svg_view(tag, svg):
        SvgViewManager.m_tag_to_svg_view[tag] = svg
        task = SvgViewManager.m_tag_to_runnable.get(tag)
        if task is not None:
            task()
            del SvgViewManager.m_tag_to_runnable[tag]

    @staticmethod
    def run_when_view_is_available(tag, task):
        SvgViewManager.m_tag_to_runnable[tag] = task

    @staticmethod
    def get_svg_view_by_tag(tag):
        return SvgViewManager.m_tag_to_svg_view.get(tag)

    def __init__(self):
        pass

    def get_name(self):
        return self.REACT_CLASS

    def create_view_instance(self, react_context):
        return SvgView(react_context)

    def update_extra_data(self, root, extra_data):
        super().update_extra_data(root, extra_data)
        root.invalidate()

    def on_drop_view_instance(self, view):
        super().on_drop_view_instance(view)
        del self.m_tag_to_svg_view[view.id]

    def needs_custom_layout_for_children(self):
        return True

    @staticmethod
    def set_tintColor(node, tintColor):
        node.setTintColor(tintColor)

    @staticmethod
    def set_color(node, color):
        node.setTintColor(color)

    @staticmethod
    def set_minX(node, minX):
        node.setMinX(minX)

    @staticmethod
    def set_minY(node, minY):
        node.setMinY(minY)

    @staticmethod
    def set_vbWidth(node, vbWidth):
        node.setVbWidth(vbWidth)

    @staticmethod
    def set_vbHeight(node, vbHeight):
        node.setVbHeight(vbHeight)

    @staticmethod
    def set_bbWidth(node, bbWidth):
        node.setBbWidth(bbWidth)

    @staticmethod
    def set_bbHeight(node, bbHeight):
        node.setBbHeight(bbHeight)

    @staticmethod
    def set_align(node, align):
        node.setAlign(align)

    @staticmethod
    def set_meet_or_slice(node, meetOrSlice):
        node.setMeetOrSlice(meetOrSlice)
