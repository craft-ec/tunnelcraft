#!/bin/bash
# Generate placeholder icons for TunnelCraft

# Create a simple PNG icon using ImageMagick or built-in tools
# First, check if we have any tools available

# Try to create a simple icon using sips (macOS built-in)
# We'll create a solid color placeholder

# Create a 1024x1024 solid blue PNG
python3 << 'PYTHON'
from PIL import Image, ImageDraw
import os

# Create a simple icon with gradient and text
size = 1024
img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Draw a rounded rectangle background
draw.rounded_rectangle([(50, 50), (size-50, size-50)], 
                       radius=150, 
                       fill=(45, 156, 219, 255))

# Draw a tunnel/shield shape
draw.polygon([
    (size//2, 200),
    (size-200, 400),
    (size-200, size-200),
    (200, size-200),
    (200, 400)
], fill=(35, 120, 180, 255))

# Inner shape
draw.polygon([
    (size//2, 300),
    (size-280, 450),
    (size-280, size-280),
    (280, size-280),
    (280, 450)
], fill=(45, 156, 219, 255))

# Save PNG
img.save('icon.png', 'PNG')
print("Generated icon.png")

# Create iconset for macOS
os.makedirs('icon.iconset', exist_ok=True)
sizes = [16, 32, 64, 128, 256, 512, 1024]
for s in sizes:
    resized = img.resize((s, s), Image.Resampling.LANCZOS)
    resized.save(f'icon.iconset/icon_{s}x{s}.png')
    if s <= 512:
        resized2x = img.resize((s*2, s*2), Image.Resampling.LANCZOS)
        resized2x.save(f'icon.iconset/icon_{s}x{s}@2x.png')

print("Generated iconset")
PYTHON

# Convert to icns (macOS)
if [ -d "icon.iconset" ]; then
    iconutil -c icns icon.iconset -o icon.icns 2>/dev/null || echo "iconutil not available"
fi

# For ico, we need a different approach
python3 << 'PYTHON'
from PIL import Image

# Load the PNG
img = Image.open('icon.png')

# Create ICO with multiple sizes
sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
icons = []
for size in sizes:
    resized = img.resize(size, Image.Resampling.LANCZOS)
    icons.append(resized)

# Save as ICO
img.save('icon.ico', format='ICO', sizes=sizes)
print("Generated icon.ico")
PYTHON

echo "Icons generated!"
ls -la icon.*
