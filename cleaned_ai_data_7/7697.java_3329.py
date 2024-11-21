from typing import Callable, Tuple

class FcgEdgePaintTransformer:
    def __init__(self, direct_color: Tuple[int, int, int], indirect_color: Tuple[int, int, int]):
        self.direct_color = color_from_tuple(direct_color)
        self.indirect_color = color_from_tuple(indirect_color)

        self.direct_colors_with_alpha = alphatize(self.direct_color)

    def apply(self, e: dict) -> Callable[[int], str]:
        if e['is_direct_edge']:
            return get_direct_edge_color(e, self)
        else:
            return indirect_color

def alphatize(c: Tuple[int, int, int]) -> list:
    result = [c]
    for i in range(1, 10):
        new_alpha = 255 - (i * 25.5)
        result.append((c[0], c[1], c[2], int(new_alpha)))
    return [color_from_tuple(c) for c in result]

def get_direct_edge_color(e: dict, transformer: 'FcgEdgePaintTransformer') -> Tuple[int, int, int]:
    if e['is_direct_edge']:
        # this allows us to make the edges fainter as the outward levels increase
        start = e['start']
        end = e['end']
        level = min(start['level'], end['level'])
        return transformer.direct_colors_with_alpha[level].getRGB()
    else:
        return transformer.indirect_color.getRGB()

def color_from_tuple(t: Tuple[int, int, int]) -> tuple:
    return (t[0], t[1], t[2])

# usage
transformer = FcgEdgePaintTransformer((125, 125, 125), (255, 0, 0))
print(transformer.apply({'is_direct_edge': True}))  # prints the direct edge color
