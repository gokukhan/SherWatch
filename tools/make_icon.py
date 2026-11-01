"""Draw the SherWatch app icon (ring + dot on a dark rounded square) as a 1024 px PNG.

Usage: python tools/make_icon.py desktop/app-icon.png
Then:  npx --prefix tools/npm tauri icon desktop/app-icon.png -o desktop/icons
"""
import sys
from PIL import Image, ImageDraw

out = sys.argv[1] if len(sys.argv) > 1 else "desktop/app-icon.png"
S = 1024
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
# background: dark rounded square
d.rounded_rectangle((0, 0, S - 1, S - 1), radius=220, fill=(20, 20, 19, 255))
# outer ring (accent blue)
c = S / 2
r_outer, w = 330, 58
d.ellipse((c - r_outer, c - r_outer, c + r_outer, c + r_outer), outline=(57, 135, 229, 255), width=w)
# faint second ring
r2 = 215
d.ellipse((c - r2, c - r2, c + r2, c + r2), outline=(57, 135, 229, 110), width=22)
# centre dot
r_dot = 95
d.ellipse((c - r_dot, c - r_dot, c + r_dot, c + r_dot), fill=(240, 239, 236, 255))
# small threat marker (orange) at upper right of ring
mx, my, mr = c + 236, c - 236, 46
d.ellipse((mx - mr, my - mr, mx + mr, my + mr), fill=(236, 131, 90, 255))
img.save(out)
print("wrote", out)
