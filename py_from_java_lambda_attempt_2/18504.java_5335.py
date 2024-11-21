Here is your Java code translated into Python:

```Python
class ViewBox:
    MOS_MEET = 0
    MOS_SLICE = 1
    MOS_NONE = 2

    @staticmethod
    def get_transform(vb_rect, e_rect, align, meet_or_slice):
        # based on https://svgwg.org/svg2-draft/coords.html#ComputingAViewportsTransform

        vb_x = vb_rect.left
        vb_y = vb_rect.top
        vb_width = vb_rect.width
        vb_height = vb_rect.height

        e_x = e_rect.left
        e_y = e_rect.top
        e_width = e_rect.width
        e_height = e_rect.height


        scale_x = e_width / vb_width
        scale_y = e_height / vb_height

        translate_x = e_x - (vb_x * scale_x)
        translate_y = e_y - (vb_y * scale_y)


        if meet_or_slice == ViewBox.MOS_NONE:
            scale = min(scale_x, scale_y)

            if scale > 1:
                translate_x -= (e_width / scale - vb_width) / 2
                translate_y -= (e_height / scale - vb_height) / 2
            else:
                translate_x -= (e_width - vb_width * scale) / 2
                translate_y -= (e_height - vb_height * scale) / 2

        elif not align == "none" and meet_or_slice == ViewBox.MOS_MEET:
            scale_x = scale_y = min(scale_x, scale_y)
        elif not align == "none" and meet_or_slice == ViewBox.MOS_SLICE:
            scale_x = scale_y = max(scale_x, scale_y)


        if "xMid" in align:
            translate_x += (e_width - vb_width * scale_x) / 2.0

        if "xMax" in align:
            translate_x += e_width - vb_width * scale_x

        if "yMid" in align:
            translate_y += (e_height - vb_height * scale_y) / 2.0

        if "YMax" in align:
            translate_y += e_height - vb_height * scale_y


        transform = Matrix()
        transform.postTranslate(translate_x, translate_y)
        transform.preScale(scale_x, scale_y)

        return transform
```

Please note that Python does not have built-in support for matrices like Java. The `Matrix` class in the above code is a simple representation of a matrix and it only provides basic operations (postTranslate and preScale).