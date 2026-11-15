# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Unit tests for the Pillow visual regression engine."""

from __future__ import annotations

import pytest
from PIL import Image

from qa_agent.visual_regression import (
    DiffConfig,
    DiffResult,
    compare_files,
    compare_images,
    content_bbox,
    save_diff,
    save_side_by_side,
)


def blank(size: tuple[int, int] = (20, 20), color: tuple[int, int, int] = (255, 255, 255)) -> Image.Image:
    return Image.new("RGB", size, color)


def with_block(color: tuple[int, int, int], box: tuple[int, int, int, int], size: tuple[int, int] = (20, 20)) -> Image.Image:
    image = blank(size)
    image.paste(color, box)
    return image


def test_identical_images_pass() -> None:
    result = compare_images(blank(), blank())
    assert result.passed is True
    assert result.diff_pixels == 0
    assert result.diff_ratio == 0.0
    assert result.bbox is None


def test_single_pixel_within_ratio_passes() -> None:
    candidate = blank()
    candidate.putpixel((0, 0), (0, 0, 0))
    result = compare_images(blank((20, 20)), candidate)
    assert result.diff_pixels == 1
    assert result.diff_ratio == pytest.approx(1 / 400)
    assert result.passed is True


def test_large_difference_fails() -> None:
    result = compare_images(blank(), with_block((0, 0, 0), (0, 0, 10, 10)))
    assert result.passed is False
    assert result.diff_pixels == 100


def test_below_tolerance_is_ignored() -> None:
    candidate = blank(color=(250, 250, 250))
    result = compare_images(blank(), candidate, DiffConfig(pixel_tolerance=10))
    assert result.diff_pixels == 0
    assert result.passed is True


def test_tolerance_zero_detects_one_level_change() -> None:
    result = compare_images(blank(), blank(color=(254, 254, 254)), DiffConfig(pixel_tolerance=0))
    assert result.diff_pixels == 400


def test_ignore_region_hides_dynamic_content() -> None:
    candidate = with_block((0, 0, 0), (0, 0, 4, 4))
    config = DiffConfig(ignore_regions=((0, 0, 4, 4),))
    result = compare_images(blank(), candidate, config)
    assert result.diff_pixels == 0
    assert result.passed is True


def test_ignore_region_boundaries() -> None:
    candidate = with_block((0, 0, 0), (10, 10, 12, 12))
    result = compare_images(blank(), candidate, DiffConfig(ignore_regions=((10, 10, 10, 10),)))
    assert result.diff_pixels == 3


def test_size_mismatch_fails() -> None:
    result = compare_images(blank((10, 10)), blank((12, 12)))
    assert result.size_mismatch is True
    assert result.passed is False
    assert (result.width, result.height) == (12, 12)


def test_bbox_of_changed_region() -> None:
    result = compare_images(blank(), with_block((0, 0, 0), (5, 6, 9, 10)))
    assert result.bbox == (5, 6, 9, 10)


def test_structural_shift_detected() -> None:
    baseline = with_block((0, 0, 0), (0, 0, 5, 5))
    candidate = with_block((0, 0, 0), (5, 0, 10, 5))
    result = compare_images(baseline, candidate, DiffConfig(max_diff_ratio=1.0))
    assert result.shift == (5, 0)


def test_no_shift_for_identical_content() -> None:
    result = compare_images(with_block((0, 0, 0), (3, 3, 8, 8)), with_block((0, 0, 0), (3, 3, 8, 8)))
    assert result.shift == (0, 0)


def test_diff_image_highlights_changes_in_red() -> None:
    result = compare_images(blank(), with_block((0, 0, 0), (0, 0, 2, 2)))
    assert result.diff_image is not None
    assert result.diff_image.getpixel((0, 0)) == (255, 0, 0)
    assert result.diff_image.getpixel((10, 10)) == (255, 255, 255)


def test_custom_highlight_color() -> None:
    result = compare_images(blank(), with_block((0, 0, 0), (0, 0, 1, 1)), DiffConfig(highlight=(0, 255, 0)))
    assert result.diff_image.getpixel((0, 0)) == (0, 255, 0)


def test_save_diff_writes_file(tmp_path) -> None:
    result = compare_images(blank(), with_block((0, 0, 0), (0, 0, 2, 2)))
    target = save_diff(result, tmp_path / "nested" / "diff.png")
    assert target.is_file()
    with Image.open(target) as saved:
        assert saved.size == (20, 20)


def test_save_diff_without_image_raises(tmp_path) -> None:
    with pytest.raises(ValueError):
        save_diff(DiffResult(True, 1, 1, 0, 1, 0.0), tmp_path / "x.png")


def test_side_by_side_width_is_sum_of_panels(tmp_path) -> None:
    baseline = tmp_path / "baseline.png"
    candidate = tmp_path / "candidate.png"
    blank().save(baseline)
    with_block((0, 0, 0), (0, 0, 2, 2)).save(candidate)
    result = compare_images(blank(), with_block((0, 0, 0), (0, 0, 2, 2)))
    target = save_side_by_side(baseline, candidate, tmp_path / "side.png", result)
    with Image.open(target) as saved:
        assert saved.size == (60, 20)


def test_side_by_side_without_diff_has_two_panels(tmp_path) -> None:
    baseline = tmp_path / "a.png"
    candidate = tmp_path / "b.png"
    blank().save(baseline)
    blank().save(candidate)
    target = save_side_by_side(baseline, candidate, tmp_path / "side.png")
    with Image.open(target) as saved:
        assert saved.size == (40, 20)


def test_compare_files(tmp_path) -> None:
    baseline = tmp_path / "a.png"
    candidate = tmp_path / "b.png"
    blank().save(baseline)
    with_block((0, 0, 0), (0, 0, 5, 5)).save(candidate)
    assert compare_files(baseline, candidate).passed is False


@pytest.mark.parametrize("kwargs", [{"pixel_tolerance": -1}, {"max_diff_ratio": -0.1}, {"max_diff_ratio": 1.5}])
def test_diff_config_validation(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        DiffConfig(**kwargs)


def test_diff_result_serializes() -> None:
    result = compare_images(blank(), with_block((0, 0, 0), (0, 0, 3, 3)))
    payload = result.to_dict()
    assert payload["passed"] is False
    assert payload["diff_pixels"] == 9
    assert payload["bbox"] == [0, 0, 3, 3]


def test_content_bbox_blank_image() -> None:
    assert content_bbox(blank()) is None


def test_content_bbox_finds_content() -> None:
    assert content_bbox(with_block((0, 0, 0), (2, 3, 8, 9))) == (2, 3, 8, 9)


def test_grayscale_input_is_converted() -> None:
    result = compare_images(Image.new("L", (10, 10), 255), Image.new("L", (10, 10), 255))
    assert result.passed is True
