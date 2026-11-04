"""Bounded image validation and safe local names for chat images."""
from __future__ import annotations

import hashlib
import io
import re
import warnings
from pathlib import Path

from datetime import datetime

from PIL import Image, ImageGrab, ImageOps, UnidentifiedImageError

MAX_IMAGE_BYTES = 16 * 1024 * 1024
MAX_IMAGE_PIXELS = 32_000_000
MAX_IMAGE_SIDE = 10_000
FORMAT_MIME = {'PNG': 'image/png', 'JPEG': 'image/jpeg', 'WEBP': 'image/webp'}
EXTENSIONS = {
    '.png': 'PNG', '.jpg': 'JPEG', '.jpeg': 'JPEG', '.webp': 'WEBP',
}
_INVALID = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *('COM' + str(i) for i in range(1, 10)),
             *('LPT' + str(i) for i in range(1, 10))}


def safe_image_name(name, image_format):
    leaf = str(name or '').replace('\\', '/').split('/')[-1].strip()
    leaf = _INVALID.sub('_', leaf)
    suffix = Path(leaf).suffix.lower()
    expected = next((ext for ext, fmt in EXTENSIONS.items()
                     if fmt == image_format and ext in (suffix, suffix.replace('jpeg', 'jpg'))), None)
    stem = Path(leaf).stem if suffix in EXTENSIONS else leaf
    stem = stem.strip(' .') or 'image'
    if stem.upper() in _RESERVED:
        stem = '_' + stem
    stem = stem[:100]
    extension = Path(leaf).suffix if expected and Path(leaf).suffix.lower() == expected else {
        'PNG': '.png', 'JPEG': '.jpg', 'WEBP': '.webp'}[image_format]
    if image_format == 'JPEG' and extension.lower() == '.jpeg':
        extension = '.jpeg'
    return stem + extension


def validate_image(data, filename):
    if type(data) is not bytes or not data:
        raise ValueError('图片数据为空或类型无效')
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError(f'图片超过{MAX_IMAGE_BYTES // (1024 * 1024)}MiB限制')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as probe:
                image_format = probe.format
                width, height = probe.size
                if image_format not in FORMAT_MIME:
                    raise ValueError(f'仅支持PNG/JPEG/WebP，当前为{image_format or "未知"}')
                if width <= 0 or height <= 0 or width > MAX_IMAGE_SIDE or height > MAX_IMAGE_SIDE:
                    raise ValueError(f'图片尺寸无效或超过{MAX_IMAGE_SIDE}像素边长限制')
                if width * height > MAX_IMAGE_PIXELS:
                    raise ValueError(f'图片超过{MAX_IMAGE_PIXELS:,}像素限制')
                if getattr(probe, 'n_frames', 1) != 1:
                    raise ValueError('暂不支持动画图片')
                probe.verify()
        with Image.open(io.BytesIO(data)) as decoded:
            decoded.load()
    except ValueError:
        raise
    except (UnidentifiedImageError, OSError, SyntaxError, Image.DecompressionBombError) as exc:
        raise ValueError('图片文件损坏或格式无效') from exc
    suffix = Path(str(filename)).suffix.lower()
    if suffix in EXTENSIONS and EXTENSIONS[suffix] != image_format:
        raise ValueError('图片扩展名与实际格式不一致')
    safe_name = safe_image_name(filename, image_format)
    return {'format': image_format, 'mime': FORMAT_MIME[image_format],
            'width': width, 'height': height, 'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'filename': safe_name}


def read_image_file(path):
    data = Path(path).read_bytes()
    metadata = validate_image(data, Path(path).name)
    return data, metadata


def read_clipboard_image():
    """Validate an image or image-file list from the Windows clipboard."""
    try:
        value = ImageGrab.grabclipboard()
    except (OSError, NotImplementedError):
        return None
    if isinstance(value, Image.Image):
        output = io.BytesIO()
        image = value.convert('RGBA') if 'A' in value.getbands() else value.convert('RGB')
        image.save(output, format='PNG')
        data = output.getvalue()
        name = 'clipboard-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.png'
        return data, validate_image(data, name)
    if isinstance(value, (list, tuple)):
        for item in value:
            try:
                path = Path(item)
                if path.is_file() and path.suffix.lower() in EXTENSIONS:
                    return read_image_file(path)
            except OSError:
                continue
    return None


def thumbnail(data, max_size=320):
    if isinstance(max_size, int):
        max_size = (max_size, max_size)
    with Image.open(io.BytesIO(data)) as source:
        source.load()
        image = ImageOps.exif_transpose(source).convert('RGBA')
        image.thumbnail(tuple(max_size), Image.Resampling.LANCZOS)
        return image.copy(), image.size
