from __future__ import annotations

import pytest

from dissect.fve.bde.eow import _iter_bitmap


@pytest.mark.parametrize(
    ("test_input", "expected"),
    [
        ((b"\xff", 8, 0, 8), [(1, 8)]),
        ((b"\xff", 8, 4, 4), [(1, 4)]),
        ((b"\x00", 8, 0, 8), [(0, 8)]),
        ((b"\x00", 8, 4, 4), [(0, 4)]),
        ((b"\xff\x00", 16, 0, 8), [(1, 8)]),
        ((b"\xff\x00", 16, 4, 8), [(1, 4), (0, 4)]),
        ((b"\x00\x00", 16, 0, 12), [(0, 12)]),
        ((b"\x00\xff", 16, 4, 8), [(0, 4), (1, 4)]),
        ((b"\xf0\xf0", 16, 0, 16), [(0, 4), (1, 4), (0, 4), (1, 4)]),
        ((b"\x0f\x0f", 16, 0, 16), [(1, 4), (0, 4), (1, 4), (0, 4)]),
        ((b"\x00", 8, 0, 6), [(0, 6)]),
        ((b"\x00", 8, 1, 6), [(0, 6)]),
        ((b"\xff", 4, 0, 8), [(1, 4)]),
        ((b"\xff", 4, 4, 8), []),
    ],
)
def test_bde_eow_bitmap_runs(test_input: tuple[bytes, int, int, int], expected: list[tuple[int, int]]) -> None:
    assert list(_iter_bitmap(*test_input)) == expected
