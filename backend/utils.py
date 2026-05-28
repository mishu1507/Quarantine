import os
import hashlib
import uuid

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

ALLOWED_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.com', '.bin'}

ALLOWED_MIME_TYPES = {
    'application/x-dosexec',
    'application/x-msdownload',
    'application/x-executable',
    'application/octet-stream',
    'application/x-msdos-program',
}

PE_MAGIC_BYTES = b'MZ'


def validate_file(file_storage):
    """
    Three-layer validation:
    1. File extension check
    2. Magic bytes check (first 2 bytes must be MZ)
    3. MIME type check via libmagic (non-fatal if unavailable)
    Returns (is_valid, error_message)
    """
    filename = file_storage.filename or ''
    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        return False, f'File extension "{ext}" not allowed. Accepted: {", ".join(sorted(ALLOWED_EXTENSIONS))}'

    file_storage.stream.seek(0)
    header = file_storage.stream.read(2)
    file_storage.stream.seek(0)

    if header != PE_MAGIC_BYTES:
        return False, 'File does not appear to be a PE executable (missing MZ header)'

    if MAGIC_AVAILABLE:
        try:
            file_storage.stream.seek(0)
            mime = magic.from_buffer(file_storage.stream.read(2048), mime=True)
            file_storage.stream.seek(0)
            if mime not in ALLOWED_MIME_TYPES:
                return False, f'MIME type "{mime}" is not a recognised PE type'
        except Exception:
            pass  # libmagic failure is non-fatal — extension + MZ are sufficient

    return True, None


def save_upload(file_storage, upload_folder):
    """
    Save the uploaded file with a UUID name to prevent filename collisions
    and avoid exposing the original filename on disk.
    Returns (stored_filename, full_path)
    """
    os.makedirs(upload_folder, exist_ok=True)
    ext = os.path.splitext(file_storage.filename or '')[1].lower() or '.bin'
    stored_name = f'{uuid.uuid4().hex}{ext}'
    full_path = os.path.join(upload_folder, stored_name)
    file_storage.stream.seek(0)
    file_storage.save(full_path)
    return stored_name, full_path


def compute_hashes(file_path):
    """Compute MD5 and SHA256 of a file efficiently using 64 KB chunks."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def cleanup_file(file_path):
    """Delete a file silently — never raises."""
    try:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass


def format_bytes(num_bytes):
    """Human-readable file size string."""
    for unit in ('B', 'KB', 'MB', 'GB'):
        if num_bytes < 1024:
            return f'{num_bytes:.1f} {unit}'
        num_bytes /= 1024
    return f'{num_bytes:.1f} TB'
