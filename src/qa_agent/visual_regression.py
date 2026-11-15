# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Zero-SaaS visual regression: Pillow pixel diff, ignore regions, shift detection.

Everything runs locally. A run produces a pass/fail verdict, a red-highlight
diff PNG, and an optional side-by-side image for client reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from PIL import Image, ImageChops

__all__ = [
    "DiffConfig",
    "DiffResult",
    "compare_files",
    "compare_images",
    "content_bbox",
    "save_diff",
    "save_side_by_side",
]


@dataclass(frozen=True)
class DiffConfig:
    pixel_tolerance: int = 8
    max_diff_ratio: float = 0.01
    ignore_regions: tuple[tuple[int, int, int, int], ...] = ()
    highlight: tuple[int, int, int] = (255, 0, 0)

    def __post_init__(self) -> None:
        if self.pixel_tolerance < 0:
            raise ValueError("pixel_tolerance must be >= 0")
        if not 0.0 <= self.max_diff_ratio <= 1.0:
            raise ValueError("max_diff_ratio must be between 0 and 1")


@dataclass
class DiffResult:
    passed: bool
    width: int
    height: int
    diff_pixels: int
    total_pixels: int
    diff_ratio: float
    size_mismatch: bool = False
    bbox: tuple[int, int, int, int] | None = None
    shift: tuple[int, int] = (0, 0)
    diff_image: Image.Image | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "width": self.width,
            "height": self.height,
            "diff_pixels": self.diff_pixels,
            "total_pixels": self.total_pixels,
            "diff_ratio": round(self.diff_ratio, 6),
            "size_mismatch": self.size_mismatch,
            "bbox": list(self.bbox) if self.bbox else None,
            "shift": list(self.shift),
        }


def _rgb(image: Image.Image) -> Image.Image:
    return image.convert("RGB") if image.mode != "RGB" else image.copy()


def _fit(image: Image.Image, size: tuple[int, int]) -> Image.Image:
    if image.size == size:
        return image
    canvas = Image.new("RGB", size, (255, 255, 255))
    canvas.paste(_rgb(image).crop((0, 0, size[0], size[1])), (0, 0))
    return canvas


def _max_channel(image: Image.Image) -> Image.Image:
    red, green, blue = image.split()
    return ImageChops.lighter(ImageChops.lighter(red, green), blue)


def content_bbox(image: Image.Image, background: tuple[int, int, int] = (255, 255, 255), tolerance: int = 8) -> tuple[int, int, int, int] | None:
    """Bounding box of non-background pixels, used for structural shift."""
    rgb = _rgb(image)
    difference = ImageChops.difference(rgb, Image.new("RGB", rgb.size, background))
    max_channel = _max_channel(difference)
    return max_channel.point(lambda value: 255 if value > tolerance else 0).getbbox()


def compare_images(
    baseline: Image.Image,
    candidate: Image.Image,
    config: DiffConfig | None = None,
) -> DiffResult:
    config = config or DiffConfig()
    first = _rgb(baseline)
    second = _rgb(candidate)
    size_mismatch = first.size != second.size

    if size_mismatch:
        width = max(first.size[0], second.size[0])
        height = max(first.size[1], second.size[1])
    else:
        width, height = first.size
    first = _fit(first, (width, height))
    second = _fit(second, (width, height))

    difference = ImageChops.difference(first, second)
    threshold = _max_channel(difference).point(lambda value: 255 if value > config.pixel_tolerance else 0)

    if config.ignore_regions:
        from PIL import ImageDraw

        draw = ImageDraw.Draw(threshold)
        for left, top, right, bottom in config.ignore_regions:
            draw.rectangle((left, top, right, bottom), fill=0)

    total = width * height
    diff_pixels = threshold.histogram()[255]
    ratio = diff_pixels / total if total else 0.0

    bbox = threshold.getbbox()
    baseline_box = content_bbox(_without_regions(first, config.ignore_regions))
    candidate_box = content_bbox(_without_regions(second, config.ignore_regions))
    shift = (
        (0, 0)
        if baseline_box is None or candidate_box is None
        else (candidate_box[0] - baseline_box[0], candidate_box[1] - baseline_box[1])
    )

    diff_image = first.copy()
    highlight = Image.new("RGB", (width, height), config.highlight)
    diff_image.paste(highlight, mask=threshold)

    return DiffResult(
        passed=not size_mismatch and ratio <= config.max_diff_ratio,
        width=width,
        height=height,
        diff_pixels=diff_pixels,
        total_pixels=total,
        diff_ratio=ratio,
        size_mismatch=size_mismatch,
        bbox=bbox,
        shift=shift,
        diff_image=diff_image,
    )


def _without_regions(image: Image.Image, regions: Sequence[tuple[int, int, int, int]]) -> Image.Image:
    if not regions:
        return image
    copy = image.copy()
    for left, top, right, bottom in regions:
        copy.paste((255, 255, 255), (left, top, right, bottom))
    return copy


def compare_files(
    baseline_path: str | Path,
    candidate_path: str | Path,
    config: DiffConfig | None = None,
) -> DiffResult:
    with Image.open(baseline_path) as baseline, Image.open(candidate_path) as candidate:
        return compare_images(baseline, candidate, config)


def save_diff(result: DiffResult, out_path: str | Path) -> Path:
    if result.diff_image is None:
        raise ValueError("diff result has no image; call compare_images first")
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    result.diff_image.save(target)
    return target


def save_side_by_side(
    baseline_path: str | Path,
    candidate_path: str | Path,
    out_path: str | Path,
    diff: DiffResult | None = None,
) -> Path:
    with Image.open(baseline_path) as baseline_image, Image.open(candidate_path) as candidate_image:
        baseline = _rgb(baseline_image)
        candidate = _rgb(candidate_image)
        panels = [baseline, candidate]
        if diff is not None and diff.diff_image is not None:
            panels.append(diff.diff_image)
        width = sum(panel.size[0] for panel in panels)
        height = max(panel.size[1] for panel in panels)
        canvas = Image.new("RGB", (width, height), (255, 255, 255))
        offset = 0
        for panel in panels:
            canvas.paste(panel, (offset, 0))
            offset += panel.size[0]
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(target)
    return target
