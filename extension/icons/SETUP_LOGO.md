# How to Add Your Logo

The "Los Pollos Hermanos" logo you attached needs to be saved here as `logo.png`.

## Quick steps:

1. **Save the attached image** (the Los Pollos Hermanos logo) to this location:
   ```
   /Users/udaypandita/Desktop/USS Project/LPH/extension/icons/logo.png
   ```

2. **Reload the extension** in Chrome:
   - Go to `chrome://extensions`
   - Find "LPH Password Manager"
   - Click the reload icon ↻

That's it! The extension will now show your logo in the toolbar and extension pages.

## Optional: Create optimized sizes

For best quality at different sizes, you can create separate icon files:

```zsh
cd "/Users/udaypandita/Desktop/USS Project/LPH/extension/icons"

# If your source image is named something else, replace "source.png" below
sips -Z 128 logo.png --out lph-128.png
sips -Z 48  logo.png --out lph-48.png
sips -Z 32  logo.png --out lph-32.png
sips -Z 16  logo.png --out lph-16.png
```

Then update `manifest.json` to reference the specific sizes instead of just `logo.png`.
