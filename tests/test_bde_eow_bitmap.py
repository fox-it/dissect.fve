import pytest

from dissect.fve.bde.eow import _iter_bitmap


@pytest.mark.parametrize(
    "test_input, expected",
    [
        ((b"\xFF", 8, 0, 8), [(1, 8)]),
        ((b"\xFF", 8, 4, 4), [(1, 4)]),
        ((b"\x00", 8, 0, 8), [(0, 8)]),
        ((b"\x00", 8, 4, 4), [(0, 4)]),
        ((b"\xFF\x00", 16, 0, 8), [(1, 8)]),
        ((b"\xFF\x00", 16, 4, 8), [(1, 4), (0, 4)]),
        ((b"\x00\x00", 16, 0, 12), [(0, 12)]),
        ((b"\x00\xFF", 16, 4, 8), [(0, 4), (1, 4)]),
        ((b"\xF0\xF0", 16, 0, 16), [(0, 4), (1, 4), (0, 4), (1, 4)]),
        ((b"\x0F\x0F", 16, 0, 16), [(1, 4), (0, 4), (1, 4), (0, 4)]),
        ((b"\x00", 8, 0, 6), [(0, 6)]),
        ((b"\x00", 8, 1, 6), [(0, 6)]),
        ((b"\xFF", 4, 0, 8), [(1, 4)]),
        ((b"\xFF", 4, 4, 8), []),
    ],
)
def test_bde_eow_bitmap_runs(test_input: tuple[bytes, int, int, int], expected: list[tuple[int, int]]) -> None:
    assert list(_iter_bitmap(*test_input)) == expected
