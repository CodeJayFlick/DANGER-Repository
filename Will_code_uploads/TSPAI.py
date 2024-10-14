import itertools


def travelling_salesman(graph, start):
    vertices = list(graph.keys())
    vertices.remove(start)
    min_path = float('inf')

    for perm in itertools.permutations(vertices):
        current_path = 0
        k = start
        for j in perm:
            current_path += graph[k][j]
            k = j
        current_path += graph[k][start]
        min_path = min(min_path, current_path)

    return min_path