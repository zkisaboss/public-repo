"""
Tests for the receipt image pre-processing pipeline.
"""

import io
from PIL import Image
from app import preprocess_receipt_image


def _make_test_image(width=800, height=600, color=(200, 180, 160)):
    """Create a synthetic RGB image and return its JPEG bytes."""
    img = Image.new('RGB', (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format='JPEG')
    return buf.getvalue()


class TestPreprocessReceiptImage:
    """Unit tests for preprocess_receipt_image()."""

    def test_returns_valid_jpeg(self):
        raw = _make_test_image()
        result = preprocess_receipt_image(raw)
        img = Image.open(io.BytesIO(result))
        assert img.format == 'JPEG'

    def test_output_is_rgb(self):
        raw = _make_test_image()
        result = preprocess_receipt_image(raw)
        img = Image.open(io.BytesIO(result))
        assert img.mode == 'RGB'

    def test_small_image_is_upscaled(self):
        raw = _make_test_image(width=500, height=400)
        result = preprocess_receipt_image(raw)
        img = Image.open(io.BytesIO(result))
        assert img.width >= 1500

    def test_large_image_is_not_upscaled(self):
        raw = _make_test_image(width=2000, height=1600)
        result = preprocess_receipt_image(raw)
        img = Image.open(io.BytesIO(result))
        assert img.width == 2000

    def test_aspect_ratio_preserved_on_upscale(self):
        raw = _make_test_image(width=500, height=1000)
        result = preprocess_receipt_image(raw)
        img = Image.open(io.BytesIO(result))
        expected_height = int(1000 * (1500 / 500))
        assert img.width == 1500
        assert img.height == expected_height

    def test_rgba_input_accepted(self):
        """RGBA images (e.g. PNGs with transparency) should still work."""
        img = Image.new('RGBA', (800, 600), color=(200, 180, 160, 255))
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        # ensure_jpeg_bytes would already handle this, but preprocess
        # should not crash if handed an RGB JPEG from ensure_jpeg_bytes
        from app import ensure_jpeg_bytes
        jpeg_bytes = ensure_jpeg_bytes(buf.getvalue())
        result = preprocess_receipt_image(jpeg_bytes)
        out = Image.open(io.BytesIO(result))
        assert out.format == 'JPEG'
