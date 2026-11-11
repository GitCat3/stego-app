"""
Steganography tool built with Drafter.

Hides a (optionally encrypted) text message or small file inside the least
significant bits (LSBs) of an image's pixels, and reveals it again.

Install:   pip install drafter pillow cryptography
Run:       python stego_app.py

IMPORTANT - what this is and is not:
  * Encryption (AES-256-GCM) protects the CONTENT of the message.
  * LSB hiding only makes the message hard to NOTICE by eye. Statistical
    tools can still detect it. This is an entertainment/learning project,
    not real security.
  * Output is always PNG. If the PNG is re-compressed (social media,
    messaging apps, JPEG conversion) the hidden message is destroyed.
"""

import hashlib
import hmac
import io
import os
import struct
import zlib
from dataclasses import dataclass

from PIL import Image as PILImage

from drafter import *

# Drafter calls its visual divider component HorizontalRule.
Divider = HorizontalRule

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    HAS_AES = True
except ImportError:  # the app still works, minus the AES option
    HAS_AES = False


# =============================================================================
# PART 1: STEGANOGRAPHY + ENCRYPTION CORE (no Drafter code in here)
# =============================================================================

METHOD_AES = "AES-256-GCM (recommended)"
METHOD_XOR = "XOR keystream (educational, weak)"
METHOD_NONE = "None (plain text)"

if HAS_AES:
    METHODS = [METHOD_AES, METHOD_XOR, METHOD_NONE]
else:
    METHODS = [METHOD_XOR, METHOD_NONE]

METHOD_IDS = {METHOD_NONE: 0, METHOD_XOR: 1, METHOD_AES: 2}
ID_TO_METHOD = {v: k for k, v in METHOD_IDS.items()}

# Header stored in the first 6 bytes of hidden data:
#   1 byte  encryption method id
#   1 byte  kind (0 = text, 1 = file)
#   4 bytes length of the body that follows
HEADER_FORMAT = ">BBI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 6

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
AES_OVERHEAD = SALT_SIZE + NONCE_SIZE + TAG_SIZE  # 44
XOR_OVERHEAD = SALT_SIZE  # 16

MAX_PIXELS = 25_000_000  # reject absurdly large covers (memory)


class StegoError(Exception):
    """Raised for any user-facing problem (bad image, too big, wrong password)."""


def overhead_for(method):
    """Bytes of extra data the chosen encryption method adds."""
    if method == METHOD_AES:
        return AES_OVERHEAD
    if method == METHOD_XOR:
        return XOR_OVERHEAD
    return 0


def capacity_bytes(width, height, method):
    """How many bytes of (compressed) payload fit in an image of this size."""
    total_bits = width * height * 3  # 1 LSB in each of R, G, B
    usable = total_bits // 8 - HEADER_SIZE - overhead_for(method)
    return max(usable, 0)


KDF_ITERATIONS = 100_000


def pbkdf2_sha256(password, salt, iterations, length=32):
    """PBKDF2-HMAC-SHA256. Uses hashlib's version when present, otherwise a
    pure-Python version (some browser Python builds, like Pyodide, ship
    hashlib without OpenSSL, so neither scrypt nor pbkdf2_hmac exist there).
    Both versions produce identical output."""
    if hasattr(hashlib, "pbkdf2_hmac"):
        return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, length)

    # Fallback (length must be <= 32: one SHA-256 block is all we need)
    base = hmac.new(password, digestmod=hashlib.sha256)
    mac = base.copy()
    mac.update(salt + b"\x00\x00\x00\x01")
    block = mac.digest()
    result = int.from_bytes(block, "big")
    for _ in range(iterations - 1):
        mac = base.copy()
        mac.update(block)
        block = mac.digest()
        result ^= int.from_bytes(block, "big")
    return result.to_bytes(32, "big")[:length]


def derive_key(password, salt):
    """Turn a password into a 32-byte key."""
    return pbkdf2_sha256(password.encode("utf-8"), salt, KDF_ITERATIONS, 32)


def xor_keystream(key, length):
    """SHA-256 in counter mode. Educational only; not a vetted cipher."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:length])


def pack_plaintext(text, file_name, file_data):
    """Return (kind, compressed_bytes). Compress BEFORE encrypting."""
    if file_data:
        name_bytes = file_name.encode("utf-8")
        raw = struct.pack(">H", len(name_bytes)) + name_bytes + file_data
        kind = 1
    else:
        raw = text.encode("utf-8")
        kind = 0
    return kind, zlib.compress(raw, 9)


def unpack_plaintext(kind, compressed):
    """Inverse of pack_plaintext. Returns (text, file_name, file_data)."""
    try:
        raw = zlib.decompress(compressed)
    except zlib.error:
        raise StegoError("Hidden data is corrupted (or the wrong password was used "
                         "with a method that cannot detect it).")
    if kind == 1:
        name_len = struct.unpack(">H", raw[:2])[0]
        file_name = raw[2:2 + name_len].decode("utf-8", errors="replace")
        return "", file_name, raw[2 + name_len:]
    return raw.decode("utf-8", errors="replace"), "", b""


def encrypt(data, password, method):
    """Encrypt bytes with the chosen method. Returns the encrypted body."""
    if method == METHOD_NONE:
        return data
    if not password:
        raise StegoError("This encryption method needs a password.")
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    if method == METHOD_XOR:
        stream = xor_keystream(key, len(data))
        return salt + bytes(a ^ b for a, b in zip(data, stream))
    if method == METHOD_AES:
        if not HAS_AES:
            raise StegoError("AES needs the 'cryptography' package (pip install cryptography).")
        nonce = os.urandom(NONCE_SIZE)
        return salt + nonce + AESGCM(key).encrypt(nonce, data, None)
    raise StegoError("Unknown encryption method.")


def decrypt(body, password, method):
    """Inverse of encrypt()."""
    if method == METHOD_NONE:
        return body
    if not password:
        raise StegoError("This image was encrypted. Enter the password.")
    salt, rest = body[:SALT_SIZE], body[SALT_SIZE:]
    key = derive_key(password, salt)
    if method == METHOD_XOR:
        stream = xor_keystream(key, len(rest))
        return bytes(a ^ b for a, b in zip(rest, stream))
    if method == METHOD_AES:
        if not HAS_AES:
            raise StegoError("AES needs the 'cryptography' package (pip install cryptography).")
        nonce, ciphertext = rest[:NONCE_SIZE], rest[NONCE_SIZE:]
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise StegoError("Wrong password, or the image was modified after embedding.")
    raise StegoError("Unknown encryption method.")


def write_bits(pixel_bytes, data):
    """Write `data` into the LSBs of `pixel_bytes`, most significant bit first."""
    if len(data) * 8 > len(pixel_bytes):
        raise StegoError("Not enough room in the image.")
    index = 0
    for byte in data:
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1
            pixel_bytes[index] = (pixel_bytes[index] & 0xFE) | bit
            index += 1


def read_bits(pixel_bytes, start_byte, count_bytes):
    """Read `count_bytes` bytes out of the LSBs, starting at byte `start_byte`."""
    out = bytearray()
    index = start_byte * 8
    for _ in range(count_bytes):
        value = 0
        for _ in range(8):
            value = (value << 1) | (pixel_bytes[index] & 1)
            index += 1
        out.append(value)
    return bytes(out)


def embed(image, text, file_name, file_data, password, method):
    """Hide a message/file in a PIL image. Returns a new RGB PIL image."""
    rgb = image.convert("RGB")
    kind, packed = pack_plaintext(text, file_name, file_data)
    body = encrypt(packed, password, method)

    room = capacity_bytes(rgb.width, rgb.height, method) + overhead_for(method)
    if len(body) > room:
        over = len(body) - room
        raise StegoError(f"Payload is {over} bytes too large for this image "
                         f"({len(body)} needed, {room} available). "
                         f"Use a bigger image or a shorter message.")

    header = struct.pack(HEADER_FORMAT, METHOD_IDS[method], kind, len(body))
    pixels = bytearray(rgb.tobytes())
    write_bits(pixels, header + body)
    return PILImage.frombytes("RGB", rgb.size, bytes(pixels))


def extract(image, password):
    """Recover (text, file_name, file_data) from a PIL image."""
    rgb = image.convert("RGB")
    pixels = rgb.tobytes()
    if len(pixels) < HEADER_SIZE * 8:
        raise StegoError("Image is too small to contain a hidden message.")

    method_id, kind, body_len = struct.unpack(HEADER_FORMAT, read_bits(pixels, 0, HEADER_SIZE))
    max_body = len(pixels) // 8 - HEADER_SIZE
    if method_id not in ID_TO_METHOD or kind not in (0, 1) or body_len > max_body:
        raise StegoError("No hidden message found in this image.")

    body = read_bits(pixels, HEADER_SIZE, body_len)
    method = ID_TO_METHOD[method_id]
    packed = decrypt(body, password, method)
    return unpack_plaintext(kind, packed)


def to_png_bytes(image):
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()



# =============================================================================
# PART 2: USER-FRIENDLY DRAFTER APP
# =============================================================================

@dataclass
class Payload:
    """One embedding job in the batch."""
    message: str
    image: Picture
    encryption_method: str
    password: str
    file_name: str
    file_data: bytes
    result: Picture | None
    status: str


@dataclass
class State:
    encryption_method: str
    image: Picture | None
    message: str
    payloads: list[Payload]
    error: str
    extracted_text: str
    extracted_file_name: str
    extracted_file_data: bytes


set_website_title("PixelVault | Image Message Hider")


def section_title(title, description):
    return [
        Header(title),
        description,
        Divider(),
    ]


@route
def index(state: State) -> Page:
    queued = len(state.payloads)

    content = [
        Header("PixelVault"),
        Header("Hide messages inside images."),
        "A simple way to hide private messages and small files inside "
        "ordinary images.",
        Divider(),

        Header("What would you like to do?"),

        Button("🔒 Hide a Message", encryption_method_select),
        Button("🔍 Reveal a Message", extract_input),

        Divider(),

        Header("How does it work?"),
        "1. Choose an image.",
        "2. Write a message or upload a file.",
        "3. Choose an encryption method.",
        "4. Download your image with the hidden content.",

        Divider(),

        Header("Your privacy matters"),
        "Your message is hidden inside the image's pixel data. "
        "Optional encryption adds another layer of protection.",

        Pre(
            "Important: This is an educational steganography tool. "
            "Hidden messages may be detectable through statistical analysis. "
            "Always use AES-256-GCM when encryption is needed.",
            style="white-space: pre-wrap; overflow-wrap: anywhere;"
        ),
    ]

    if queued:
        content.extend([
            Divider(),
            Header("Your pending images"),
            f"You have {queued} message(s) waiting to be embedded.",
            Button("Create my images", image_output),
        ])

    return Page(state, content)


@route
def encryption_method_select(state: State) -> Page:
    return Page(state, [
        Header("Step 1 of 3: Choose your protection"),
        "How would you like to protect your message?",

        Divider(),

        Header("AES-256-GCM"),
        "Recommended. Strong encryption that protects your message "
        "and detects incorrect passwords or modifications.",

        Header("XOR"),
        "Educational option. Uses a basic XOR keystream and is NOT "
        "secure for real-world use.",

        Header("No encryption"),
        "Your message will be hidden without a password.",

        Divider(),

        SelectBox("method", METHODS, state.encryption_method),

        Button("Continue", save_method),
        Button("Back to Home", index),
    ])


@route
def save_method(state: State, method: str) -> Page:
    if method not in METHODS:
        state.error = "Please select a valid encryption method."
        return error_route(state)

    state.encryption_method = method
    return image_input(state)


@route
def image_input(state: State) -> Page:
    return Page(state, [
        Header("Step 2 of 3: Choose an image"),
        "Select the image that will carry your hidden message.",

        Divider(),

        Header("Upload your cover image"),
        "Choose a PNG, JPEG, or other supported image format.",
        "Your finished image will always be saved as PNG.",

        FileUpload("upload", accept="image/*"),

        Divider(),

        Button("Continue", save_image),
        Button("Go Back", encryption_method_select),
    ])


@route
def save_image(state: State, upload: Picture | None) -> Page:
    if upload is None:
        state.error = "Please select an image before continuing."
        return error_route(state)

    try:
        pil = upload.to_pil()

        if pil.width * pil.height > MAX_PIXELS:
            state.error = "This image is too large. Please choose an image "
            state.error += "smaller than 25 megapixels."
            return error_route(state)

        if capacity_bytes(
            pil.width, pil.height, state.encryption_method
        ) < 1:
            state.error = "This image is too small to store a message."
            return error_route(state)

        state.image = Picture(pil.convert("RGB"))

    except Exception:
        state.error = "We couldn't open that image. Please try another file."
        return error_route(state)

    return message_input(state)


def capacity_summary(state, message):
    pil = state.image.to_pil()

    capacity = capacity_bytes(
        pil.width,
        pil.height,
        state.encryption_method
    )

    _, packed = pack_plaintext(message, "", b"")

    return len(packed), capacity


@route
def message_input(state: State) -> Page:
    if state.image is None:
        state.error = "Please upload an image first."
        return error_route(state)

    used, capacity = capacity_summary(state, state.message)

    percent = (
        0 if capacity == 0
        else min(100, round(100 * used / capacity))
    )

    if used > capacity:
        status = (
            f"Your message is {used - capacity} bytes "
            "over the available limit."
        )
    else:
        status = (
            f"Your message uses approximately {used} "
            f"of {capacity} available bytes."
        )

    return Page(state, [
        Header("Step 3 of 3: Add your message"),

        "Your image is ready. Now decide what you want to hide.",

        Divider(),

        Header("Image preview"),
        Image(state.image, width=400),

        f"Selected encryption: {state.encryption_method}",

        Divider(),

        Header("Write your message"),
        "Type the text you want to hide inside your image.",

        TextArea("message", state.message),

        Divider(),

        Header("Or attach a file"),
        "Optional: Upload a small file instead of hiding text.",

        FileUpload("attachment"),

        Divider(),

        Header("Password protection"),
        "Enter a password if your selected encryption method "
        "requires one. You will need the same password to reveal "
        "your message later.",

        TextBox("password", "", kind="password"),

        Divider(),

        Header("Storage capacity"),
        status,
        Meter(
            min(used, capacity),
            min=0,
            max=max(capacity, 1)
        ),

        Button("Check storage capacity", check_capacity),
        Button("Add to my images", add_payload),
        Button("Choose another image", image_input),
    ])


@route
def check_capacity(
    state: State,
    message: str,
    attachment: DrafterBinaryFile | None,
    password: str
) -> Page:
    state.message = message

    return message_input(state)


@route
def add_payload(
    state: State,
    message: str,
    attachment: DrafterBinaryFile | None,
    password: str
) -> Page:

    state.message = message

    has_file = (
        attachment is not None
        and len(attachment.content) > 0
    )

    if not has_file and not message.strip():
        state.error = "Please enter a message or attach a file."
        return error_route(state)

    if state.image is None:
        state.error = "Please upload an image first."
        return error_route(state)

    if state.encryption_method != METHOD_NONE and not password:
        state.error = "Please enter a password to protect your message."
        return error_route(state)

    file_name = attachment.filename if has_file else ""
    file_data = attachment.content if has_file else b""

    pil = state.image.to_pil()

    _, packed = pack_plaintext(message, file_name, file_data)

    needed = len(packed) + overhead_for(state.encryption_method)

    room = (
        capacity_bytes(
            pil.width,
            pil.height,
            state.encryption_method
        )
        + overhead_for(state.encryption_method)
    )

    if needed > room:
        state.error = (
            f"Your content is {needed - room} bytes "
            "too large for this image. Try a larger image "
            "or a smaller message."
        )
        return error_route(state)

    state.payloads.append(
        Payload(
            message,
            state.image,
            state.encryption_method,
            password,
            file_name,
            file_data,
            None,
            "queued"
        )
    )

    state.message = ""
    state.image = None

    return Page(state, [
        Header("Your message is ready!"),

        "Your content has been added to the processing queue.",

        f"Messages waiting: {len(state.payloads)}",

        Divider(),

        Button("Add another message", encryption_method_select),
        Button("Create my hidden images", image_output),
        Button("Return Home", index),
    ])


@route
def image_output(state: State) -> Page:
    if not state.payloads:
        state.error = "There are no messages waiting to be embedded."
        return error_route(state)

    content = [
        Header("Your hidden images"),
        "Your images have been processed. Download each PNG below.",
        Divider(),
    ]

    for number, payload in enumerate(state.payloads, start=1):
        try:
            result = embed(
                payload.image.to_pil(),
                payload.message,
                payload.file_name,
                payload.file_data,
                payload.password,
                payload.encryption_method
            )

            png = to_png_bytes(result)

            reloaded = PILImage.open(io.BytesIO(png))

            text, name, data = extract(
                reloaded,
                payload.password
            )

            if text != payload.message or data != payload.file_data:
                raise StegoError(
                    "Verification failed. The saved image "
                    "could not be read back correctly."
                )

            payload.result = Picture(png)
            payload.status = "done"

        except Exception as problem:
            payload.status = f"Failed: {problem}"

        content.extend([
            Header(f"Image {number}", 2),
            f"Encryption: {payload.encryption_method}",
            Divider(),
        ])

        if payload.status == "done":
            content.extend([
                Image(payload.result, width=400),

                "Your hidden content was successfully verified.",

                Download(
                    f"Download PNG #{number}",
                    f"hidden_{number}.png",
                    payload.result
                ),

                Divider(),
            ])
        else:
            content.append(payload.status)

    content.extend([
        Header("Important reminder"),

        "Always send the finished PNG as a file or document. "
        "Do not convert it to JPEG or send it through services "
        "that compress images, because this can destroy the "
        "hidden information.",

        Button("Finish", finished),
    ])

    return Page(state, content)


@route
def finished(state: State) -> Page:
    state.payloads = []
    state.image = None
    state.message = ""

    return Page(state, [
        Header("All finished!"),

        "Your hidden images are ready. Keep your password safe "
        "and remember that the original image should not be "
        "shared alongside the modified image.",

        Button("Start Again", index),
    ])


# =============================================================================
# REVEAL HIDDEN CONTENT
# =============================================================================

@route
def extract_input(state: State) -> Page:
    return Page(state, [
        Header("Reveal a hidden message"),

        "Upload an image created with PixelVault to recover "
        "its hidden message or file.",

        Divider(),

        Header("Select your image"),
        FileUpload("upload", accept="image/png"),

        Divider(),

        Header("Enter your password"),
        "If the image was encrypted, enter the original password. "
        "Leave blank if encryption was not used.",

        TextBox("password", "", kind="password"),

        Button("Reveal Hidden Content", extract_result),
        Button("Back to Home", index),
    ])


@route
def extract_result(
    state: State,
    upload: Picture | None,
    password: str
) -> Page:

    if upload is None:
        state.error = "Please upload an image first."
        return error_route(state)

    try:
        text, name, data = extract(
            upload.to_pil(),
            password
        )

    except StegoError as problem:
        state.error = str(problem)
        return error_route(state)

    state.extracted_text = text
    state.extracted_file_name = name
    state.extracted_file_data = data

    content = [
        Header("Hidden content successfully recovered!"),
        Divider(),
    ]

    if name:
        safe_name = os.path.basename(name) or "extracted_file"

        content.extend([
            Header("Recovered file"),
            f"Filename: {safe_name}",
            f"File size: {len(data)} bytes",

            Download(
                "Download recovered file",
                safe_name,
                data,
                content_type="application/octet-stream"
            ),
        ])

    else:
        content.extend([
            Header("Your recovered message"),
            Pre(text),
        ])

    content.extend([
        Divider(),
        Button("Reveal another image", extract_input),
        Button("Return Home", index),
    ])

    return Page(state, content)


# =============================================================================
# ERROR HANDLING
# =============================================================================

@route
def error_route(state: State) -> Page:
    message = state.error
    state.error = ""

    return Page(state, [
        Header("Something went wrong"),

        message,

        Divider(),

        "Please check your input and try again.",

        Button("Return Home", index),
    ])


hide_debug_information()

start_server(
    State(
        METHODS[0],
        None,
        "",
        [],
        "",
        "",
        "",
        b""
    )
)
