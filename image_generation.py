"""Isolated OpenAI Images API service and file store; never uses chat or research state."""
from __future__ import annotations

import asyncio
import base64
import binascii
from contextlib import contextmanager
import importlib.util
import json
import os
import sqlite3
import uuid
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Callable

import httpx
from database_safety import validate_test_database_path

API_URL = "https://api.openai.com/v1/images/generations"
SUPPORTED_MODEL = "gpt-image-2.6-flare"
SIZES = ("1024x1024", "1536x1024", "1024x1536")
QUALITIES = ("low", "medium", "high")
FORMATS = ("png", "webp", "jpeg")
MIME_BY_FORMAT = {"png": "image/png", "webp": "image/webp", "jpeg": "image/jpeg"}
EXT_BY_FORMAT = {"png": "png", "webp": "webp", "jpeg": "jpg"}
MAX_PROMPT_CHARS = 2_000
MAX_RESPONSE_BYTES = 25 * 1024 * 1024
MAX_IMAGE_BYTES = 18 * 1024 * 1024
MAX_STORAGE_BYTES = 500 * 1024 * 1024
MAX_IMAGE_PIXELS = 8_294_400
MAX_DAILY_REQUESTS = 3
TIMEOUT_SECONDS = 90
IMAGE_INPUT_USD_PER_MILLION = 8.0
TEXT_INPUT_USD_PER_MILLION = 5.0
IMAGE_OUTPUT_USD_PER_MILLION = 30.0
# OpenAI's current calculator page shows an 823-output-token example. It is illustrative,
# not a preset-specific quote or a spending cap.
REFERENCE_OUTPUT_TOKENS = 823
REFERENCE_OUTPUT_COST_USD = REFERENCE_OUTPUT_TOKENS * IMAGE_OUTPUT_USD_PER_MILLION / 1_000_000


class ImageGenerationError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class ImageRecord:
    image_id: str
    media_type: str
    width: int
    height: int
    byte_length: int
    model: str
    size: str
    quality: str
    output_format: str
    created_at: str
    estimated_cost_usd: float
    token_usage: dict[str, int] | None


def _default_storage_root() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    base = Path(local) if local else Path.home() / "AppData" / "Local"
    return base / "GENESIS_AI" / "images"


def _pillow_available() -> bool:
    try:
        return importlib.util.find_spec("PIL") is not None
    except (ImportError, ValueError):
        return False


def validate_image_bytes(data: bytes, expected_format: str, expected_size: str) -> tuple[int, int]:
    """Fully decode and validate the raster response. Requires the declared Pillow dependency."""
    try:
        from PIL import Image, ImageFile, UnidentifiedImageError
    except ImportError as exc:
        raise ImageGenerationError("image_validator_unavailable",
            "Image validation is unavailable. Install the application's declared image dependency.", 503) from exc

    expected_dimensions = tuple(int(part) for part in expected_size.split("x", 1))
    expected_pillow_format = {"png": "PNG", "webp": "WEBP", "jpeg": "JPEG"}[expected_format]
    if not data or len(data) > MAX_IMAGE_BYTES:
        raise ImageGenerationError("invalid_image", "The generated image exceeded the allowed size.", 502)
    if ImageFile.LOAD_TRUNCATED_IMAGES:
        raise ImageGenerationError("image_validator_unsafe", "Image validation is not safely configured.", 503)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(data)) as image:
                if image.format != expected_pillow_format:
                    raise ImageGenerationError("invalid_image", "The provider returned an unexpected image format.", 502)
                width, height = image.size
                if (width, height) != expected_dimensions or width * height > MAX_IMAGE_PIXELS:
                    raise ImageGenerationError("invalid_image", "The provider returned unexpected image dimensions.", 502)
                image.verify()
            with Image.open(BytesIO(data)) as image:
                if image.format != expected_pillow_format:
                    raise ImageGenerationError("invalid_image", "The provider returned an unexpected image format.", 502)
                image.load()
    except ImageGenerationError:
        raise
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError, Image.DecompressionBombError,
            Image.DecompressionBombWarning) as exc:
        raise ImageGenerationError("invalid_image", "The provider returned an invalid image.", 502) from exc
    return width, height


class ImageGenerationService:
    """One-request image generation service with separate metadata/quota storage."""

    def __init__(self, *, api_key: str, enabled: bool, model: str = SUPPORTED_MODEL,
                 storage_root: Path | None = None, project_root: Path | None = None,
                 research_root: Path | None = None, daily_request_limit: int = MAX_DAILY_REQUESTS,
                 timeout_seconds: int = TIMEOUT_SECONDS, max_storage_bytes: int = MAX_STORAGE_BYTES,
                 transport: httpx.AsyncBaseTransport | None = None,
                 image_validator: Callable[[bytes, str, str], tuple[int, int]] | None = None):
        self._api_key = api_key.strip()
        self.enabled = bool(enabled)
        self.model = model.strip()
        self.storage_root = Path(storage_root) if storage_root else _default_storage_root()
        self.project_root = Path(project_root).resolve() if project_root else None
        self.research_root = Path(research_root).resolve() if research_root else None
        self.daily_request_limit = daily_request_limit
        self.timeout_seconds = timeout_seconds
        self.max_storage_bytes = max_storage_bytes
        self.transport = transport
        self.image_validator = image_validator or validate_image_bytes
        self._validator_is_available = image_validator is not None or _pillow_available()
        self._generation_lock = asyncio.Lock()

    @property
    def ready(self) -> bool:
        return bool(self.enabled and self._api_key and self.model == SUPPORTED_MODEL and self._validator_is_available)

    def safe_status(self) -> dict:
        if not self.enabled:
            reason = "disabled"
        elif not self._api_key:
            reason = "credentials_missing"
        elif self.model != SUPPORTED_MODEL:
            reason = "unsupported_model"
        elif not self._validator_is_available:
            reason = "image_validator_unavailable"
        else:
            reason = None
        return {
            "enabled": self.enabled,
            "available": self.ready,
            "model": self.model or None,
            "reason": reason,
            "account_access_checked": False,
            "max_prompt_chars": MAX_PROMPT_CHARS,
            "sizes": list(SIZES),
            "qualities": list(QUALITIES),
            "formats": list(FORMATS),
            "daily_request_limit": self.daily_request_limit,
            "cost": {
                "text_input_usd_per_million_tokens": TEXT_INPUT_USD_PER_MILLION,
                "image_input_usd_per_million_tokens": IMAGE_INPUT_USD_PER_MILLION,
                "image_output_usd_per_million_tokens": IMAGE_OUTPUT_USD_PER_MILLION,
                "illustrative_output_tokens": REFERENCE_OUTPUT_TOKENS,
                "illustrative_output_cost_usd": REFERENCE_OUTPUT_COST_USD,
                "notice": "Illustrative official calculator example only; not a quote for the selected settings or a spending cap. Prompt input is billed separately and actual image token use varies.",
            },
        }

    def _resolved_root(self, *, create: bool) -> Path:
        root = self.storage_root.expanduser().resolve(strict=False)
        blocked = [p for p in (self.project_root, self.research_root) if p is not None]
        for other in blocked:
            if root == other or other in root.parents or root in other.parents:
                raise ImageGenerationError("unsafe_storage_root", "Image storage must be isolated from the project and research directories.", 503)
        validate_test_database_path(root / "image_metadata.sqlite3", project_root=Path(__file__).resolve().parent)
        if create:
            root.mkdir(parents=True, exist_ok=True)
        resolved = root.resolve(strict=create)
        for other in blocked:
            if resolved == other or other in resolved.parents or resolved in other.parents:
                raise ImageGenerationError("unsafe_storage_root", "Image storage must be isolated from the project and research directories.", 503)
        return resolved

    def _connect_store(self) -> sqlite3.Connection:
        root = self._resolved_root(create=True)
        db_path = validate_test_database_path(root / "image_metadata.sqlite3", project_root=Path(__file__).resolve().parent)
        db = sqlite3.connect(db_path, timeout=10)
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS image_daily_attempts (
                utc_date TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL CHECK(attempts >= 0)
            );
            CREATE TABLE IF NOT EXISTS image_reservations (
                reservation_id TEXT PRIMARY KEY,
                reserved_bytes INTEGER NOT NULL,
                started_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS generated_images (
                image_id TEXT PRIMARY KEY,
                account_id TEXT,
                filename TEXT NOT NULL UNIQUE,
                media_type TEXT NOT NULL,
                width INTEGER NOT NULL,
                height INTEGER NOT NULL,
                byte_length INTEGER NOT NULL,
                model TEXT NOT NULL,
                size TEXT NOT NULL,
                quality TEXT NOT NULL,
                output_format TEXT NOT NULL,
                created_at TEXT NOT NULL,
                estimated_cost_usd REAL NOT NULL,
                token_usage_json TEXT
            );
        """)
        columns = {row[1] for row in db.execute("PRAGMA table_info(generated_images)")}
        if "account_id" not in columns:
            # Existing records remain NULL-owned and therefore inaccessible to
            # account-scoped retrieval. Never infer an owner from a browser.
            db.execute("ALTER TABLE generated_images ADD COLUMN account_id TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS generated_images_account_created_idx ON generated_images(account_id,created_at DESC)")
        return db

    @contextmanager
    def _store_db(self):
        db = self._connect_store()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def attempts_today(self) -> int:
        try:
            metadata_path = validate_test_database_path(self.storage_root / "image_metadata.sqlite3",
                project_root=Path(__file__).resolve().parent)
        except RuntimeError:
            if os.getenv("GENESIS_ENV", "") == "test":
                return 0
            raise
        if not metadata_path.is_file():
            return 0
        try:
            with self._store_db() as db:
                row = db.execute("SELECT attempts FROM image_daily_attempts WHERE utc_date=?",
                    (datetime.now(timezone.utc).date().isoformat(),)).fetchone()
            return int(row[0]) if row else 0
        except (OSError, sqlite3.Error, ImageGenerationError):
            return 0

    def _reserve_attempt(self) -> str:
        reservation_id = str(uuid.uuid4())
        today = datetime.now(timezone.utc).date().isoformat()
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(seconds=max(self.timeout_seconds * 3, 300))).isoformat()
        db = self._connect_store()
        try:
            db.execute("BEGIN IMMEDIATE")
            # Release only stale accounting reservations after a prior process died; never delete image files.
            db.execute("DELETE FROM image_reservations WHERE started_at < ?", (cutoff,))
            row = db.execute("SELECT attempts FROM image_daily_attempts WHERE utc_date=?", (today,)).fetchone()
            if row and row[0] >= self.daily_request_limit:
                raise ImageGenerationError("daily_limit", "The daily image request limit has been reached.", 429)
            used = db.execute("SELECT COALESCE(SUM(byte_length),0) FROM generated_images").fetchone()[0]
            reserved = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM image_reservations").fetchone()[0]
            if used + reserved + MAX_IMAGE_BYTES > self.max_storage_bytes:
                raise ImageGenerationError("storage_limit", "Image storage is full. Delete existing generated images before trying again.", 507)
            db.execute("INSERT INTO image_daily_attempts(utc_date,attempts) VALUES(?,1) ON CONFLICT(utc_date) DO UPDATE SET attempts=attempts+1", (today,))
            db.execute("INSERT INTO image_reservations(reservation_id,reserved_bytes,started_at) VALUES(?,?,?)",
                (reservation_id, MAX_IMAGE_BYTES, now.isoformat()))
            db.commit()
            return reservation_id
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _release_reservation(self, reservation_id: str) -> None:
        try:
            with self._store_db() as db:
                db.execute("DELETE FROM image_reservations WHERE reservation_id=?", (reservation_id,))
        except (OSError, sqlite3.Error, ImageGenerationError):
            pass

    async def _bounded_body(self, response: httpx.Response, limit: int) -> bytes:
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > limit:
                    raise ImageGenerationError("response_too_large", "The image provider response exceeded the allowed size.", 502)
            except ValueError:
                raise ImageGenerationError("invalid_provider_response", "The image provider returned an invalid response.", 502) from None
        chunks = bytearray()
        async for chunk in response.aiter_bytes():
            if len(chunks) + len(chunk) > limit:
                raise ImageGenerationError("response_too_large", "The image provider response exceeded the allowed size.", 502)
            chunks.extend(chunk)
        return bytes(chunks)

    @staticmethod
    def _provider_error(status: int, body: bytes) -> ImageGenerationError:
        code = ""
        try:
            parsed = json.loads(body)
            detail = parsed.get("error", {}) if isinstance(parsed, dict) else {}
            if isinstance(detail, dict):
                code = str(detail.get("code") or detail.get("type") or "").lower()
        except (ValueError, UnicodeDecodeError):
            pass
        if status in (401, 403):
            return ImageGenerationError("provider_access", "OpenAI image access failed. Check credentials and organization/model access.", 503)
        if status == 404 or code in {"model_not_found", "unsupported_model", "invalid_model"}:
            return ImageGenerationError("model_unavailable", "The configured image model is unavailable to this account. No substitute model was selected.", 503)
        if status == 429 and code in {"insufficient_quota", "billing_hard_limit_reached", "insufficient_credits"}:
            return ImageGenerationError("insufficient_credits", "OpenAI reports insufficient API credits or a spending limit. Add credits or review billing; no retry was made.", 402)
        if status == 429:
            return ImageGenerationError("rate_limited", "The image provider rate limit was reached. No retry was made.", 429)
        if status == 400:
            return ImageGenerationError("invalid_provider_request", "The image model rejected these settings or the prompt.", 400)
        if status >= 500:
            return ImageGenerationError("provider_unavailable", "The image provider is temporarily unavailable. No retry was made.", 503)
        return ImageGenerationError("provider_error", "The image provider rejected the request. No retry was made.", 502)

    @staticmethod
    def _usage(payload: dict) -> dict[str, int] | None:
        usage = payload.get("usage")
        if not isinstance(usage, dict):
            return None
        result = {key: usage[key] for key in ("input_tokens", "output_tokens", "total_tokens")
                  if isinstance(usage.get(key), int) and not isinstance(usage.get(key), bool)}
        return result or None

    def _save_image(self, image_id: str, reservation_id: str, image_bytes: bytes, *, account_id: str, output_format: str,
                    dimensions: tuple[int, int], size: str, quality: str,
                    token_usage: dict[str, int] | None) -> ImageRecord:
        root = self._resolved_root(create=True)
        extension = EXT_BY_FORMAT[output_format]
        filename = f"{image_id}.{extension}"
        target = root / filename
        if target.exists():
            raise ImageGenerationError("storage_error", "Could not safely store the generated image.", 500)
        try:
            with target.open("xb") as output:
                output.write(image_bytes)
                output.flush()
                os.fsync(output.fileno())
            if target.resolve(strict=True).parent != root:
                raise ImageGenerationError("unsafe_storage_path", "Could not safely store the generated image.", 500)
            created = datetime.now(timezone.utc).isoformat()
            usage_json = json.dumps(token_usage, separators=(",", ":")) if token_usage else None
            with self._store_db() as db:
                db.execute("DELETE FROM image_reservations WHERE reservation_id=?", (reservation_id,))
                db.execute("INSERT INTO generated_images(image_id,account_id,filename,media_type,width,height,byte_length,model,size,quality,output_format,created_at,estimated_cost_usd,token_usage_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                    image_id, account_id, filename, MIME_BY_FORMAT[output_format], dimensions[0], dimensions[1],
                    len(image_bytes), self.model, size, quality, output_format, created,
                    REFERENCE_OUTPUT_COST_USD, usage_json))
            return ImageRecord(image_id, MIME_BY_FORMAT[output_format], dimensions[0], dimensions[1],
                len(image_bytes), self.model, size, quality, output_format, created,
                REFERENCE_OUTPUT_COST_USD, token_usage)
        except ImageGenerationError:
            target.unlink(missing_ok=True)
            raise
        except (OSError, sqlite3.Error):
            target.unlink(missing_ok=True)
            raise ImageGenerationError("storage_error", "Could not safely store the generated image.", 500) from None

    async def generate(self, *, prompt: str, size: str, quality: str, output_format: str,
                       account_id: str | None,
                       confirm_cloud_cost: bool) -> ImageRecord:
        if not isinstance(account_id, str) or not account_id.strip():
            raise ImageGenerationError("not_found", "Image generation is unavailable for this session.", 404)
        if not self.ready:
            state = self.safe_status()["reason"]
            if state == "unsupported_model":
                raise ImageGenerationError("model_unavailable", "The configured image model is unsupported. No substitute model was selected.", 503)
            if state == "credentials_missing":
                raise ImageGenerationError("provider_not_configured", "OpenAI image generation is not configured.", 503)
            if state == "image_validator_unavailable":
                raise ImageGenerationError("image_validator_unavailable", "Image validator is unavailable; install the declared image-validation dependency before enabling image generation.", 503)
            raise ImageGenerationError("disabled", "Image generation is disabled. Enable both cloud and image generation in local settings.", 503)
        if not confirm_cloud_cost:
            raise ImageGenerationError("confirmation_required", "Confirm the cloud request and cost disclosure before generating.", 400)
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt.strip()) > MAX_PROMPT_CHARS:
            raise ImageGenerationError("invalid_prompt", f"Prompt must contain 1 to {MAX_PROMPT_CHARS} characters.", 422)
        prompt = prompt.strip()
        if size not in SIZES or quality not in QUALITIES or output_format not in FORMATS:
            raise ImageGenerationError("invalid_settings", "Choose a supported image size, quality, and format.", 422)

        async with self._generation_lock:
            self._active_reservation_id = self._reserve_attempt()
            reservation_id = self._active_reservation_id
            try:
                payload = {"model": self.model, "prompt": prompt, "n": 1,
                    "size": size, "quality": quality, "output_format": output_format}
                timeout = httpx.Timeout(self.timeout_seconds, connect=min(15, self.timeout_seconds))
                # HTTPX's default transport has retries=0; the service contains no retry loop.
                kwargs = {"timeout": timeout, "verify": True, "follow_redirects": False}
                if self.transport is not None:
                    kwargs["transport"] = self.transport
                try:
                    async with httpx.AsyncClient(**kwargs) as client:
                        async with client.stream("POST", API_URL,
                            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
                            json=payload) as response:
                            body = await self._bounded_body(response, 64 * 1024 if response.is_error else MAX_RESPONSE_BYTES)
                            if response.is_error:
                                raise self._provider_error(response.status_code, body)
                            if response.status_code != 200:
                                raise ImageGenerationError("unexpected_provider_status", "The image provider returned an unexpected status.", 502)
                            if "application/json" not in response.headers.get("content-type", "").lower():
                                raise ImageGenerationError("invalid_provider_response", "The image provider returned an invalid response.", 502)
                except ImageGenerationError:
                    raise
                except httpx.TimeoutException:
                    raise ImageGenerationError("timeout", "Image generation timed out. The request may still have been billed; check usage before trying again.", 504) from None
                except httpx.HTTPError:
                    raise ImageGenerationError("network_error", "Could not connect to the image provider. No automatic retry was made; check usage before trying again.", 502) from None

                try:
                    decoded = json.loads(body)
                except (ValueError, UnicodeDecodeError):
                    raise ImageGenerationError("invalid_provider_response", "The image provider returned malformed data.", 502) from None
                items = decoded.get("data") if isinstance(decoded, dict) else None
                if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
                    raise ImageGenerationError("invalid_provider_response", "The image provider did not return exactly one image.", 502)
                encoded = items[0].get("b64_json")
                if not isinstance(encoded, str) or not encoded or len(encoded) > ((MAX_IMAGE_BYTES + 2) // 3) * 4:
                    raise ImageGenerationError("invalid_provider_response", "The image provider returned an invalid image payload.", 502)
                try:
                    image_bytes = base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError):
                    raise ImageGenerationError("invalid_provider_response", "The image provider returned an invalid image payload.", 502) from None
                if not image_bytes or len(image_bytes) > MAX_IMAGE_BYTES:
                    raise ImageGenerationError("response_too_large", "The generated image exceeded the allowed size.", 502)
                try:
                    dimensions = self.image_validator(image_bytes, output_format, size)
                except ImageGenerationError:
                    raise
                except Exception:
                    raise ImageGenerationError("invalid_image", "The provider returned an image that failed validation.", 502) from None
                if dimensions != tuple(int(part) for part in size.split("x")):
                    raise ImageGenerationError("invalid_image", "The provider returned unexpected image dimensions.", 502)
                image_id = str(uuid.uuid4())
                token_usage = self._usage(decoded)
                return self._save_image(image_id, reservation_id, image_bytes, account_id=account_id, output_format=output_format,
                    dimensions=dimensions, size=size, quality=quality, token_usage=token_usage)
            finally:
                self._release_reservation(reservation_id)

    def load_image(self, image_id: str, *, account_id: str | None) -> tuple[ImageRecord, bytes]:
        if not isinstance(account_id, str) or not account_id.strip():
            raise ImageGenerationError("not_found", "Image not found.", 404)
        try:
            parsed_id = str(uuid.UUID(image_id))
        except (ValueError, AttributeError, TypeError):
            raise ImageGenerationError("not_found", "Image not found.", 404) from None
        if parsed_id != image_id.lower():
            raise ImageGenerationError("not_found", "Image not found.", 404)
        try:
            with self._store_db() as db:
                row = db.execute("SELECT image_id,filename,media_type,width,height,byte_length,model,size,quality,output_format,created_at,estimated_cost_usd,token_usage_json FROM generated_images WHERE image_id=? AND account_id=?",
                    (parsed_id, account_id)).fetchone()
            if row is None:
                raise ImageGenerationError("not_found", "Image not found.", 404)
            root = self._resolved_root(create=False)
            path = (root / row[1]).resolve(strict=True)
            if path.parent != root or path.name != row[1] or not path.is_file() or path.stat().st_size != row[5] or row[5] > MAX_IMAGE_BYTES:
                raise ImageGenerationError("not_found", "Image not found.", 404)
            with path.open("rb") as handle:
                content = handle.read(MAX_IMAGE_BYTES + 1)
            if len(content) != row[5] or len(content) > MAX_IMAGE_BYTES:
                raise ImageGenerationError("not_found", "Image not found.", 404)
            usage = json.loads(row[12]) if row[12] else None
            record = ImageRecord(row[0], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11], usage)
            return record, content
        except ImageGenerationError:
            raise
        except (OSError, sqlite3.Error, ValueError, TypeError):
            raise ImageGenerationError("not_found", "Image not found.", 404) from None

    async def delete_account_images(self, account_id: str) -> int:
        """Idempotently remove an account's isolated image objects and metadata."""
        if not isinstance(account_id, str) or not account_id.strip():
            raise ImageGenerationError("not_found", "Account images not found.", 404)
        async with self._generation_lock:
            metadata = self.storage_root.expanduser().resolve(strict=False) / "image_metadata.sqlite3"
            if not metadata.is_file():
                return 0
            with self._store_db() as db:
                rows = db.execute("SELECT image_id,filename FROM generated_images WHERE account_id=?", (account_id,)).fetchall()
            root = self._resolved_root(create=False)
            for row in rows:
                filename = row[1]
                if not isinstance(filename, str) or Path(filename).name != filename or filename in {".", ".."}:
                    raise ImageGenerationError("unsafe_storage_path", "Image storage requires operator review.", 503)
                candidate = root / filename
                try:
                    resolved = candidate.resolve(strict=False)
                    if resolved.parent != root or resolved.name != filename:
                        raise ImageGenerationError("unsafe_storage_path", "Image storage requires operator review.", 503)
                    resolved.unlink(missing_ok=True)
                except OSError:
                    raise ImageGenerationError("storage_unavailable", "Account deletion is pending image cleanup.", 503) from None
            with self._store_db() as db:
                deleted = db.execute("DELETE FROM generated_images WHERE account_id=?", (account_id,)).rowcount
            return deleted
