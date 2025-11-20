Place your extension logo here as logo.png (square, at least 128x128). The extension will scale it at runtime for the toolbar icon.

Optional static icons for manifest (if you want them):
- lph-16.png
- lph-32.png
- lph-48.png
- lph-128.png

To generate these on macOS from a source image, run:

sips -Z 128 source.png --out lph-128.png
sips -Z 48  source.png --out lph-48.png
sips -Z 32  source.png --out lph-32.png
sips -Z 16  source.png --out lph-16.png
