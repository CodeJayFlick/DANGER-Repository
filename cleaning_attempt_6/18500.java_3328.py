class AlignmentBaseline:
    baseline = "baseline"
    text_bottom = "text-bottom"
    alphabetic = "alphabetic"
    ideographic = "ideographic"
    middle = "middle"
    central = "central"
    mathematical = "mathematical"
    text_top = "text-top"
    bottom = "bottom"
    center = "center"
    top = "top"

    text_before_edge = "text-before-edge"
    text_after_edge = "text-after-edge"
    before_edge = "before-edge"
    after_edge = "after-edge"
    hanging = "hanging"

class Direction:
    ltr = 1
    rtl = 2

class FontVariantLigatures:
    normal = 1
    none = 0

class FontStyle:
    normal = 1
    italic = 2
    oblique = 3

class FontWeight:
    Normal = "normal"
    Bold = "bold"
    w100 = "100"
    w200 = "200"
    w300 = "300"
    w400 = "400"
    w500 = "500"
    w600 = "600"
    w700 = "700"
    w800 = "800"
    w900 = "900"

    Bolder = "bolder"
    Lighter = "lighter"

class TextAnchor:
    start = 1
    middle = 2
    end = 3

class TextDecoration:
    None = "none"
    Underline = "underline"
    Overline = "overline"
    LineThrough = "line-through"
    Blink = "blink"

class TextLengthAdjust:
    spacing = 1
    spacing_and_glyphs = 2

class TextPathMethod:
    align = 1
    stretch = 0

class TextPathMidLine:
    sharp = 1
    smooth = 0

class TextPathSide:
    left = 1
    right = 2

class TextPathSpacing:
    auto = 1
    exact = 0

# Mapping of strings to enums for AlignmentBaseline, FontWeight and TextDecoration
alignment_to_enum = {v: k for k, v in locals().items() if isinstance(k, str) and not k.startswith('__')}
weight_to_enum = {k: v for k, v in locals().items() if isinstance(v, int)}
decoration_to_enum = {k: v for k, v in locals().items() if isinstance(v, str)}

# Mapping of strings to enums
alignmentToEnum = alignment_to_enum.copy()
weightToEnum = weight_to_enum.copy()
decorationToEnum = decoration_to_enum.copy()

def get_alignment(s):
    return AlignmentBaseline.__dict__.get(s)

def get_font_weight(s):
    return FontWeight.__dict__.get(s)

def get_text_decoration(s):
    return TextDecoration.__dict__.get(s)
