import struct, math, os

C0 = (56, 97, 251)
C1 = (34, 211, 238)

def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))

def in_glyph(px, py):
    stroke_a = 8.0 <= py <= 16.0 and abs(px - (8.0 + (py - 8.0))) <= 1.15
    stroke_b = 16.0 <= py <= 24.0 and abs(px - (16.0 - (py - 16.0))) <= 1.15
    underscore = 21.0 <= py <= 23.2 and 19.0 <= px <= 26.5
    return stroke_a or stroke_b or underscore

def pixel(x, y, size):
    d = size / 32.0
    cx, cy = (x + 0.5) * d, (y + 0.5) * d
    t = min(1.0, max(0.0, (cx + cy) / 64.0))
    r, g, b = lerp(C0, C1, t)
    corner = 7.5
    dx = min(cx, 32.0 - cx)
    dy = min(cy, 32.0 - cy)
    inside = True
    alpha = 255
    if dx < corner and dy < corner:
        dist = math.hypot(corner - dx, corner - dy)
        if dist > corner:
            if dist <= corner + 1.1:
                alpha = int(255 * (1.0 - (dist - corner) / 1.1))
                if alpha <= 8:
                    return None
            else:
                return None
    if in_glyph(cx, cy):
        return (238, 245, 255, alpha)
    return (b, g, r, alpha)

def make_size(size):
    rows = []
    for y in range(size - 1, -1, -1):
        row = bytearray()
        for x in range(size):
            p = pixel(x, y, size)
            if p is None:
                row += b"\x00\x00\x00\x00"
            else:
                row += bytes((p[2], p[1], p[0], p[3]))
        rows.append(bytes(row))
    xor = b"".join(rows)
    and_stride = ((size + 31) // 32) * 4
    and_mask = b"\x00" * (and_stride * size)
    hdr = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, len(xor) + len(and_mask), 0, 0, 0, 0)
    return hdr + xor + and_mask

def main():
    imgs = [(16, make_size(16)), (32, make_size(32)), (48, make_size(48)), (256, make_size(256))]
    out = struct.pack("<HHH", 0, 1, len(imgs))
    off = 6 + 16 * len(imgs)
    entries = b""
    data = b""
    for size, blob in imgs:
        w = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(blob), off)
        data += blob
        off += len(blob)
    dest = os.path.join(os.path.dirname(__file__), "..", "src", "host", "app.ico")
    with open(dest, "wb") as f:
        f.write(out + entries + data)
    print("wrote", dest)

if __name__ == "__main__":
    main()
