class UseView:
    def __init__(self):
        pass  # Initialize with ReactContext if needed in actual implementation.

    @property
    def href(self):
        return self._href

    @href.setter
    def href(self, value):
        self._href = value
        self.invalidate()

    @property
    def x(self):
        return self._x

    @x.setter
    def x(self, value):
        if isinstance(value, str):  # Assuming 'Dynamic' is a string type in Python.
            self._x = SVGLength.from_string(value)
        else:
            raise ValueError("Invalid type for `x` attribute.")
        self.invalidate()

    @property
    def y(self):
        return self._y

    @y.setter
    def y(self, value):
        if isinstance(value, str):  # Assuming 'Dynamic' is a string type in Python.
            self._y = SVGLength.from_string(value)
        else:
            raise ValueError("Invalid type for `y` attribute.")
        self.invalidate()

    @property
    def width(self):
        return self._w

    @width.setter
    def width(self, value):
        if isinstance(value, str):  # Assuming 'Dynamic' is a string type in Python.
            self._w = SVGLength.from_string(value)
        else:
            raise ValueError("Invalid type for `width` attribute.")
        self.invalidate()

    @property
    def height(self):
        return self._h

    @height.setter
    def height(self, value):
        if isinstance(value, str):  # Assuming 'Dynamic' is a string type in Python.
            self._h = SVGLength.from_string(value)
        else:
            raise ValueError("Invalid type for `height` attribute.")
        self.invalidate()

    def draw(self, canvas, paint, opacity):
        template = get_svg_view().get_defined_template(self.href)

        if template is None:
            FLog.w(ReactConstants.TAG, f"`Use` element expected a pre-defined svg template as `href` prop, "
                                         f"template named: {self.href} is not defined.")
            return

        canvas.translate(relative_on_width(self._x), relative_on_height(self._y))
        if isinstance(template, RenderableView):
            (RenderableView)template).merge_properties(self)

        count = template.save_and_setup_canvas(canvas)
        self.clip(canvas, paint)

        if isinstance(template, SymbolView):
            symbol = (SymbolView)template
            symbol.draw_symbol(canvas, paint, opacity * self.opacity,
                                relative_on_width(self._w), relative_on_height(self._h))
        else:
            template.draw(canvas, paint, opacity * self.opacity)

        self.set_rect_client(template.get_rect_client())

        template.restore_canvas(canvas)
        if isinstance(template, RenderableView):
            (RenderableView)template).reset_properties()

    def hit_test(self, src):
        if not self.invertible or not self.transform_invertible:
            return -1

        dst = [0.0] * 2
        self.inv_matrix.map_points(dst, src)
        self.inv_transform.map_points(dst)

        template = get_svg_view().get_defined_template(self.href)
        if template is None:
            FLog.w(ReactConstants.TAG, f"`Use` element expected a pre-defined svg template as `href` prop, "
                                         f"template named: {self.href} is not defined.")
            return -1

        hit_child = template.hit_test(dst)
        if hit_child != -1:
            return (template.is_responsible() or hit_child != template.id) and self.id
        else:
            return -1

    def get_path(self, canvas, paint):
        template = get_svg_view().get_defined_template(self.href)

        if template is None:
            FLog.w(ReactConstants.TAG, f"`Use` element expected a pre-defined svg template as `href` prop, "
                                         f"template named: {self.href} is not defined.")
            return None

        path = template.get_path(canvas, paint)
        use = Path()
        m = Matrix()
        m.set_translate(relative_on_width(self._x), relative_on_height(self._y))
        path.transform(m, use)

        return use
