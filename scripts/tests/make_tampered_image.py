"""
Tampered test images for the attestation experiments.

A tampered image is the reference firmware image of a build in which part of the attestation test region
(main/device_integrity_verification/attestation_test_region.c, 4 KB of constant data never used by the
firmware) is overwritten with random bytes. The checksum and the SHA-256 digest of the image are updated,
so that the bootloader accepts it and the device works normally: only the attestation can tell it apart.

    python make_tampered_image.py --build-dir build --out-dir build_tampered --size 4096 [--seed 1]

The module also gives the probability with which one attestation detects the difference between two
images, from the parameters of the HAtt measurement in the firmware (hatt_protocol.h): every word of the
image is read in each iteration, and a bit is drawn at a uniformly random position of each word, so a word
that differs from the reference in d of its 32 bits goes unnoticed in one iteration with probability
(1 - d/32) for every bit read.
"""
import argparse
import hashlib
import json
import os
import random
import shutil

REGION_SIZE = 4096
REGION_BYTE = 0x5A
BLOCK_SIZE = 64          # HATT_WORDS_PER_BLOCK words of 4 bytes
WORD_SIZE = 4
ITERATIONS = 4           # HATT_ITERATIONS
BITS_PER_WORD = 1        # HATT_BITS_PER_WORD
IMAGE_MAGIC = 0xE9
HASH_APPENDED_OFFSET = 23
HASH_SIZE = 32


def attested_length(image: bytes) -> int:
    """Length of the attested memory: the image without its appended SHA-256 digest."""
    if image[0] != IMAGE_MAGIC:
        raise ValueError("not an ESP32 application image")
    return len(image) - HASH_SIZE if image[HASH_APPENDED_OFFSET] == 1 else len(image)


def image_id(image: bytes) -> str:
    """Identifier returned by /test/hatt: first 8 bytes of the SHA-256 of the attested memory."""
    return hashlib.sha256(image[:attested_length(image)]).hexdigest()[:16]


def find_test_region(image: bytes) -> int:
    pattern = bytes([REGION_BYTE]) * REGION_SIZE
    start = image.find(pattern)
    if start < 0 or image.find(pattern, start + REGION_SIZE) >= 0:
        raise ValueError("attestation test region not found (or not unique) in the image")
    if start % BLOCK_SIZE:
        raise ValueError(f"attestation test region at offset {start:#x} is not aligned to a block")
    return start


def tamper(image: bytes, size: int, seed: int = 1) -> bytes:
    """Overwrites the first size bytes of the test region with random bytes and fixes checksum and digest."""
    if not 0 < size <= REGION_SIZE:
        raise ValueError(f"size must be in 1..{REGION_SIZE}")
    start = find_test_region(image)
    rng = random.Random(seed)
    patch = bytes(rng.randrange(256) for _ in range(size))
    out = bytearray(image)
    out[start:start + size] = patch

    # The checksum byte (XOR of the segment data with 0xEF) closes the segments, before the digest.
    hash_appended = image[HASH_APPENDED_OFFSET] == 1
    checksum_pos = len(image) - (HASH_SIZE if hash_appended else 0) - 1
    delta = 0
    for a, b in zip(image[start:start + size], patch):
        delta ^= a ^ b
    out[checksum_pos] ^= delta
    if hash_appended:
        out[-HASH_SIZE:] = hashlib.sha256(bytes(out[:-HASH_SIZE])).digest()
    return bytes(out)


def word_distances(reference: bytes, image: bytes) -> list:
    """Hamming distance of every attested word that differs between the two images."""
    n = attested_length(reference)
    if attested_length(image) != n:
        raise ValueError("the two images have a different length")
    distances = []
    for off in range(0, n, WORD_SIZE):
        a = int.from_bytes(reference[off:off + WORD_SIZE].ljust(WORD_SIZE, b"\0"), "little")
        b = int.from_bytes(image[off:off + WORD_SIZE].ljust(WORD_SIZE, b"\0"), "little")
        if a != b:
            distances.append(bin(a ^ b).count("1"))
    return distances


def predicted_detection(reference: bytes, image: bytes, iterations: int = ITERATIONS,
                        bits_per_word: int = BITS_PER_WORD) -> float:
    """Probability that one attestation of image against reference returns a wrong proof."""
    miss = 1.0
    for d in word_distances(reference, image):
        miss *= (1.0 - d / 32.0) ** (bits_per_word * iterations)
    return 1.0 - miss


def make_tampered_build(build_dir: str, out_dir: str, size: int, seed: int = 1) -> dict:
    """Copies the files flashed from build_dir into out_dir, with the application image tampered."""
    with open(os.path.join(build_dir, "flasher_args.json")) as f:
        flasher_args = json.load(f)
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)
    shutil.copy2(os.path.join(build_dir, "flasher_args.json"), out_dir)
    for key in ("bootloader", "partition-table"):
        rel = flasher_args[key]["file"]
        os.makedirs(os.path.join(out_dir, os.path.dirname(rel)), exist_ok=True)
        shutil.copy2(os.path.join(build_dir, rel), os.path.join(out_dir, rel))
    app_rel = flasher_args["app"]["file"]
    with open(os.path.join(build_dir, app_rel), "rb") as f:
        reference = f.read()
    tampered = tamper(reference, size, seed)
    with open(os.path.join(out_dir, app_rel), "wb") as f:
        f.write(tampered)
    distances = word_distances(reference, tampered)
    return {
        "size": size, "seed": seed, "region_offset": find_test_region(reference),
        "changed_words": len(distances), "changed_bits": sum(distances),
        "reference_id": image_id(reference), "image_id": image_id(tampered),
        "predicted_detection": predicted_detection(reference, tampered),
    }


def main():
    parser = argparse.ArgumentParser(description="Build a tampered test image from a reference build")
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--size", type=int, default=REGION_SIZE, help="bytes of the test region overwritten")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    info = make_tampered_build(args.build_dir, args.out_dir, args.size, args.seed)
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
