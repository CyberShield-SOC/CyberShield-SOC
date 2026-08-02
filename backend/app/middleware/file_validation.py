import re

from fastapi import UploadFile, HTTPException

# Allowed file extensions and their accepted MIME types
ALLOWED_EXTENSIONS = {".log", ".csv", ".json", ".jsonl", ".txt"}
ALLOWED_MIME_TYPES = {
    "text/plain",
    "text/csv",
    "application/csv",
    "application/vnd.ms-excel",
    "application/octet-stream",
    "application/json",
    "application/x-ndjson",
    "application/jsonlines",
}
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_FILENAME_LENGTH = 255

# Anything that isn't a plain filename character. Path separators, drive
# letters, and NUL/control bytes are stripped so a crafted name like
# "../../etc/passwd" or "C:\\Windows\\win.ini" can never be interpreted as a
# path once it reaches storage or a response payload.
_UNSAFE_FILENAME_CHARS = re.compile(r'[\\/\x00-\x1f<>:"|?*]')


def sanitize_filename(filename: str | None) -> str:
    """
    Reduce a client-supplied filename to a safe basename for storage/display.

    Strips directory components (both `/` and `\\` separators so this is safe
    on POSIX and Windows deployments alike), drops NUL/control and reserved
    characters, collapses leading dots so the name can't resolve to a hidden
    file or a `..` traversal segment, and bounds the length to fit the
    database column.
    """

    name = (filename or "").strip()
    # Take only the final path segment, regardless of which separator style
    # the client used.
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = _UNSAFE_FILENAME_CHARS.sub("_", name)
    name = name.lstrip(".") or "unnamed"
    return name[:MAX_FILENAME_LENGTH]


def validate_log_file(file: UploadFile, content: bytes) -> str:
    """
    Validates the uploaded file against CyberShield SOC rules.
    Raises HTTPException on any violation so FastAPI returns clean JSON.
    Returns the sanitized filename for the caller to use in storage/response.
    """
    # --- Filename sanitization ---
    safe_filename = sanitize_filename(file.filename)

    # --- Extension check ---
    ext = "." + safe_filename.rsplit(".", 1)[-1].lower() if "." in safe_filename else ""

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail={
                "success": False,
                "error": (
                    f"Invalid file type '{ext}'. "
                    f"Accepted extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
                ),
                "code": "INVALID_FILE_TYPE",
            },
        )

    # --- MIME type check ---
    content_type = (file.content_type or "").split(";")[0].strip()
    if content_type and content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415,
            detail={
                "success": False,
                "error": (
                    f"Invalid MIME type '{content_type}'. "
                    f"Accepted types: {', '.join(sorted(ALLOWED_MIME_TYPES))}"
                ),
                "code": "INVALID_MIME_TYPE",
            },
        )

    # --- Size check ---
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "success": False,
                "error": f"File too large. Maximum allowed size is {MAX_FILE_SIZE_BYTES // 1024 // 1024} MB.",
                "code": "FILE_TOO_LARGE",
            },
        )

    # --- Empty file check ---
    if not content.strip():
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "error": "Uploaded file is empty.",
                "code": "EMPTY_FILE",
            },
        )

    # NUL bytes are a strong binary-file signal and should never reach a text parser.
    if b"\x00" in content:
        raise HTTPException(
            status_code=415,
            detail={
                "success": False,
                "error": "Uploaded files must contain plain-text log data.",
                "code": "BINARY_FILE",
            },
        )

    return safe_filename
