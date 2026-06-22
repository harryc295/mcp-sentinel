"""Renders transcript.txt into two terminal-style PNGs for posting -- a
two-slide story: what sentinel found at connect time, then what it blocked
live. Local rendering only, nothing uploaded anywhere."""
import pathlib

from PIL import Image, ImageDraw, ImageFont

HERE = pathlib.Path(__file__).parent
FONT_PATH = r"C:\Windows\Fonts\CascadiaMono.ttf"
FONT_SIZE = 19
PAD = 26
LINE_H = 28
TITLEBAR_H = 42

BG = (13, 17, 23)
TITLEBAR_BG = (22, 27, 34)
FG = (201, 209, 217)
GREEN = (63, 185, 80)
RED = (248, 81, 73)
CYAN = (121, 192, 255)
YELLOW = (210, 168, 91)
MUTED = (110, 118, 129)


def color_for(line: str):
    if line.startswith("="):
        return CYAN
    if line.startswith("$"):
        return YELLOW
    if "BLOCKED" in line:
        return RED
    if "ALLOWED" in line:
        return GREEN
    return FG


def render(lines: list[str], out_path: pathlib.Path, title: str):
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    title_font = ImageFont.truetype(FONT_PATH, FONT_SIZE - 2)

    probe = Image.new("RGB", (10, 10))
    probe_draw = ImageDraw.Draw(probe)
    max_width = max(probe_draw.textlength(line, font=font) for line in lines)

    width = int(max_width) + PAD * 2
    height = TITLEBAR_H + PAD * 2 + LINE_H * len(lines)
    img = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(img)

    draw.rectangle([0, 0, width, TITLEBAR_H], fill=TITLEBAR_BG)
    for i, c in enumerate([RED, YELLOW, GREEN]):
        cx = 18 + i * 22
        draw.ellipse([cx, TITLEBAR_H // 2 - 6, cx + 12, TITLEBAR_H // 2 + 6], fill=c)
    tw = draw.textlength(title, font=title_font)
    draw.text((width / 2 - tw / 2, TITLEBAR_H / 2 - 9), title, font=title_font, fill=MUTED)

    y = TITLEBAR_H + PAD
    for line in lines:
        draw.text((PAD, y), line, font=font, fill=color_for(line))
        y += LINE_H

    img.save(out_path)
    print(f"wrote {out_path}  ({width}x{height})")


def main():
    text = (HERE / "transcript.txt").read_text().splitlines()
    split_marker = "$ tools/call read_file   # normal attachment read"
    split_at = next(i for i, line in enumerate(text) if line == split_marker)

    setup_lines = text[:split_at]
    while setup_lines and not setup_lines[-1].strip():
        setup_lines.pop()

    live_lines = ["=" * 72, "mcp-sentinel demo: live tool calls", "=" * 72, ""] + text[split_at:]

    render(setup_lines, HERE / "demo-1-startup-scan.png", "mcp-sentinel -- connect-time scan")
    render(live_lines, HERE / "demo-2-live-blocks.png", "mcp-sentinel -- live tool calls")


if __name__ == "__main__":
    main()
