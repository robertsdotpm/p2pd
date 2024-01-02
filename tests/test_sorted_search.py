from p2pd.utils import sorted_search

assert(
    sorted_search(
        [1, 40], 324324
    ) == 1
)

assert(
    sorted_search(
        [1, 40], 40
    ) == 1
)

assert(
    sorted_search(
        [1, 40], 3
    ) == 1
)

assert(
    sorted_search(
        [1, 40], 1
    ) == 0
)

assert(
    sorted_search(
        [1, 40], 0
    ) == 0
)

assert(
    sorted_search(
        [1], 1
    ) == 0
)

assert(
    sorted_search(
        [1], 0
    ) == 0
)


assert(
    sorted_search(
        [5, 10, 15], 20
    ) == 2
)

assert(
    sorted_search(
        [5, 10, 15], 10
    ) == 1
)
assert(
    sorted_search(
        [5, 10, 15], 15
    ) == 2
)

assert(
    sorted_search(
        [5, 10, 15], 5
    ) == 0
)

assert(
    sorted_search(
        [5, 10, 15], 3
    ) == 0
)

assert(
    sorted_search(
        [5, 10, 15], 6
    ) == 1
)

assert(
    sorted_search(
        [5, 10, 15, 20], 20
    ) == 3
)

assert(
    sorted_search(
        [5, 10, 15, 22, 40, 80, 100], 30
    ) == 4
)