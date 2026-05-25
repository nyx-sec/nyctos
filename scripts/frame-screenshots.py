#!/usr/bin/env python3
"""Frame Nyctos screenshots for the README.

This is adapted from the Nyx screenshot framer. It keeps the same
four-corner gradient treatment, but writes to explicit output paths so
raw captures can stay untouched.

Usage:
    python3 scripts/frame-screenshots.py source.png output.png
    python3 scripts/frame-screenshots.py --gif --duration-ms 1800 output.gif frame-a.png frame-b.png
    python3 scripts/frame-screenshots.py --defaults
"""
from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

PAD_L, PAD_T = 100, 60
PAD_R, PAD_B = 100, 61
MAX_INNER_W, MAX_INNER_H = 1600, 992
CORNER_RADIUS = 14
SHADOW_BLUR = 26
SHADOW_ALPHA = 70
SHADOW_OFFSET_Y = 18

GRAD_TL = (114, 243, 215)
GRAD_TR = (255, 106, 162)
GRAD_BL = (248, 197, 107)
GRAD_BR = (76, 201, 255)

DEFAULTS = [
    (
        "assets/screenshots/raw/project-workspace.png",
        "assets/screenshots/project-workspace.png",
    ),
    (
        "assets/screenshots/raw/live-pentest.png",
        "assets/screenshots/live-pentest.png",
    ),
    (
        "assets/screenshots/raw/verified-vulnerabilities.png",
        "assets/screenshots/verified-vulnerabilities.png",
    ),
    (
        "assets/screenshots/raw/vulnerability-detail.png",
        "assets/screenshots/vulnerability-detail.png",
    ),
]


def make_gradient(width: int, height: int) -> Image.Image:
    top = Image.new("RGB", (width, 1))
    bottom = Image.new("RGB", (width, 1))
    top_px = top.load()
    bottom_px = bottom.load()

    for x in range(width):
        t = x / (width - 1) if width > 1 else 0
        top_px[x, 0] = lerp_color(GRAD_TL, GRAD_TR, t)
        bottom_px[x, 0] = lerp_color(GRAD_BL, GRAD_BR, t)

    out = Image.new("RGB", (width, height))
    for y in range(height):
        t = y / (height - 1) if height > 1 else 0
        out.paste(Image.blend(top, bottom, t), (0, y))
    return out


def lerp_color(left: tuple[int, int, int], right: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return (
        int(left[0] + (right[0] - left[0]) * t),
        int(left[1] + (right[1] - left[1]) * t),
        int(left[2] + (right[2] - left[2]) * t),
    )


def resize_to_fit(image: Image.Image) -> Image.Image:
    width, height = image.size
    scale = min(MAX_INNER_W / width, MAX_INNER_H / height)
    target = (max(1, round(width * scale)), max(1, round(height * scale)))
    if target == image.size:
        return image
    return image.resize(target, Image.LANCZOS)


def rounded(image: Image.Image, radius: int) -> Image.Image:
    mask = Image.new("L", image.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, image.width, image.height), radius=radius, fill=255)
    out = image.convert("RGBA")
    out.putalpha(mask)
    return out


def shadow(size: tuple[int, int]) -> Image.Image:
    width, height = size
    layer = Image.new("RGBA", (width + 80, height + 80), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    draw.rounded_rectangle(
        (40, 40 + SHADOW_OFFSET_Y, width + 40, height + 40 + SHADOW_OFFSET_Y),
        radius=CORNER_RADIUS,
        fill=(15, 23, 42, SHADOW_ALPHA),
    )
    return layer.filter(ImageFilter.GaussianBlur(SHADOW_BLUR))


def frame_image(src: Path) -> Image.Image:
    inner = resize_to_fit(Image.open(src).convert("RGB"))
    outer_w = inner.width + PAD_L + PAD_R
    outer_h = inner.height + PAD_T + PAD_B
    canvas = make_gradient(outer_w, outer_h).convert("RGBA")

    shadow_layer = shadow(inner.size)
    canvas.alpha_composite(shadow_layer, (PAD_L - 40, PAD_T - 40))

    rounded_inner = rounded(inner, CORNER_RADIUS)
    canvas.alpha_composite(rounded_inner, (PAD_L, PAD_T))
    return canvas.convert("RGB")


def frame(src: Path, dest: Path) -> None:
    canvas = frame_image(src)

    dest.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(dest, "PNG", optimize=True)
    print(f"framed {src} -> {dest}")


def frame_gif(frame_paths: list[Path], dest: Path, duration_ms: int) -> None:
    frames = [frame_image(path).convert("P", palette=Image.ADAPTIVE) for path in frame_paths]
    if not frames:
        raise SystemExit("no frames passed for gif")
    dest.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        dest,
        save_all=True,
        append_images=frames[1:],
        duration=duration_ms,
        loop=0,
        disposal=2,
        optimize=False,
    )
    print(f"framed gif -> {dest}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--defaults", action="store_true")
    parser.add_argument("--gif", action="store_true")
    parser.add_argument("--duration-ms", type=int, default=1800)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.gif:
        if len(args.paths) < 2:
            raise SystemExit("usage: frame-screenshots.py --gif output.gif frame-a.png [...]")
        dest = Path(args.paths[0])
        frame_paths = [Path(path) for path in args.paths[1:]]
        for src in frame_paths:
            if not src.is_file():
                raise SystemExit(f"missing source image: {src}")
        frame_gif(frame_paths, dest, max(args.duration_ms, 100))
        return 0

    jobs: list[tuple[Path, Path]] = []
    if args.defaults:
        jobs.extend((Path(src), Path(dest)) for src, dest in DEFAULTS)

    if args.paths:
        if len(args.paths) % 2 != 0:
            raise SystemExit("pass source/output pairs")
        pairs = zip(args.paths[0::2], args.paths[1::2], strict=True)
        jobs.extend((Path(src), Path(dest)) for src, dest in pairs)

    if not jobs:
        raise SystemExit("pass source/output pairs or --defaults")

    for src, dest in jobs:
        if not src.is_file():
            raise SystemExit(f"missing source image: {src}")
        frame(src, dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
