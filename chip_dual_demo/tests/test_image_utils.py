import io
import unittest
from unittest.mock import patch

from PIL import Image

import image_utils


def png_bytes(size=(40, 30), color=(20, 100, 180)):
    output = io.BytesIO()
    Image.new('RGB', size, color).save(output, format='PNG')
    return output.getvalue()


class ImageValidationTests(unittest.TestCase):
    def test_valid_png_and_jpeg_metadata(self):
        png = png_bytes()
        meta = image_utils.validate_image(png, 'photo.png')
        self.assertEqual((meta['format'], meta['width'], meta['height']), ('PNG', 40, 30))
        self.assertEqual(meta['mime'], 'image/png')
        self.assertEqual(meta['sha256'], __import__('hashlib').sha256(png).hexdigest())
        output = io.BytesIO(); Image.new('RGB', (20, 10), 'red').save(output, format='JPEG')
        self.assertEqual(image_utils.validate_image(output.getvalue(), 'x.jpg')['mime'], 'image/jpeg')

    def test_corrupt_unsupported_and_mismatched_extension_rejected(self):
        data = png_bytes()
        with self.assertRaises(ValueError): image_utils.validate_image(b'not an image', 'bad.png')
        with self.assertRaises(ValueError): image_utils.validate_image(data[:-7], 'broken.png')
        with self.assertRaises(ValueError): image_utils.validate_image(data, 'photo.jpg')
        self.assertEqual(image_utils.validate_image(data, '../photo.png')['filename'], 'photo.png')

    def test_byte_limit_and_thumbnail(self):
        with self.assertRaises(ValueError):
            image_utils.validate_image(b'x' * (image_utils.MAX_IMAGE_BYTES + 1), 'large.png')
        thumb, size = image_utils.thumbnail(png_bytes((800, 600)), 200)
        self.assertLessEqual(size[0], 200)
        self.assertLessEqual(size[1], 200)
        self.assertEqual(thumb.mode, 'RGBA')

    def test_safe_png_name(self):
        self.assertEqual(image_utils.safe_image_name('clipboard.png', 'PNG'), 'clipboard.png')
        self.assertEqual(image_utils.safe_image_name('../../evil.PNG', 'PNG'), 'evil.PNG')
        self.assertEqual(image_utils.safe_image_name('CON.png', 'PNG'), '_CON.png')
        self.assertEqual(image_utils.safe_image_name('', 'PNG'), 'image.png')

    def test_clipboard_bitmap_is_encoded_as_validated_png(self):
        image = Image.open(io.BytesIO(png_bytes()))
        with patch.object(image_utils.ImageGrab, 'grabclipboard', return_value=image):
            data, metadata = image_utils.read_clipboard_image()
        self.assertEqual(metadata['format'], 'PNG')
        self.assertEqual((metadata['width'], metadata['height']), (40, 30))
        self.assertTrue(metadata['filename'].endswith('.png'))
        self.assertTrue(data.startswith(b'\x89PNG\r\n\x1a\n'))
        with patch.object(image_utils.ImageGrab, 'grabclipboard', return_value='plain text'):
            self.assertIsNone(image_utils.read_clipboard_image())
