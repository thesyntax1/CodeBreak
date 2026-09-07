# Minimal, dependency-free Compound File Binary (OLE2) writer used by the
# fixture generator to build a realistic legacy-Office compound document.
import struct

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
NOSTREAM = 0xFFFFFFFF


class CNode:
    def __init__(self, name, etype, data=b"", children=None):
        self.name = name          # str
        self.etype = etype        # 5 root, 1 storage, 2 stream
        self.data = data          # bytes for streams
        self.children = children or []
        self.sid = None
        self.left = NOSTREAM
        self.right = NOSTREAM
        self.child = NOSTREAM
        self.start = 0
        self.size = 0
        self.chain = []


def stream(name, data):
    return CNode(name, 2, data=data)


def storage(name, children):
    return CNode(name, 1, children=children)


def _bst(nodes):
    nodes = sorted(nodes, key=lambda n: n.name.lower())
    def bal(lo, hi):
        if lo > hi:
            return NOSTREAM
        mid = (lo + hi) // 2
        n = nodes[mid]
        n.left = bal(lo, mid - 1)
        n.right = bal(mid + 1, hi)
        return n.sid
    return bal(0, len(nodes) - 1)


def serialize(root_children, path):
    SSZ = 512
    sids = []
    def add(n):
        n.sid = len(sids)
        sids.append(n)
    add(CNode("Root Entry", 5))
    def adds(kids):
        for k in kids:
            add(k)
        for k in kids:
            if k.etype == 1:
                adds(k.children)
    adds(root_children)

    for s in sids:
        if s.etype == 2 and s.data:
            if len(s.data) < 4096:
                s.data = s.data + b"\x00" * (4096 - len(s.data))
            s.size = len(s.data)

    root = sids[0]
    root.child = _bst(root_children)
    for s in sids:
        if s.etype == 1:
            s.child = _bst(s.children)

    def cd(a, b):
        return (a + b - 1) // b

    stream_sectors = []
    n_data = 0
    for s in sids:
        if s.etype == 2:
            ns = cd(len(s.data), SSZ)
            stream_sectors.append((s, ns))
            n_data += ns
    dir_sectors = cd(len(sids) * 128, SSZ) if len(sids) * 128 else 1

    def total_est(nfat):
        return n_data + dir_sectors + nfat

    n_fat = 1
    while cd(total_est(n_fat), 128) != n_fat:
        n_fat = cd(total_est(n_fat), 128)

    fat = {}
    cursor = 0
    for (s, ns) in stream_sectors:
        if ns == 0:
            s.start = ENDOFCHAIN
            continue
        s.chain = list(range(cursor, cursor + ns))
        cursor += ns
        s.start = s.chain[0]
        for i, c in enumerate(s.chain):
            fat[c] = s.chain[i + 1] if i + 1 < ns else ENDOFCHAIN
    dir_start = cursor
    dir_chain = list(range(dir_start, dir_start + dir_sectors))
    cursor += dir_sectors
    for i, c in enumerate(dir_chain):
        fat[c] = dir_chain[i + 1] if i + 1 < dir_sectors else ENDOFCHAIN
    fat_start = cursor
    fat_chain = list(range(fat_start, fat_start + n_fat))
    cursor += n_fat
    for i, c in enumerate(fat_chain):
        fat[c] = fat_chain[i + 1] if i + 1 < n_fat else ENDOFCHAIN
    total_sectors = cursor
    for i in range(total_sectors):
        if i not in fat:
            fat[i] = FREESECT

    # file offset of sector index i is 512 + i*512
    img = bytearray(512 + total_sectors * SSZ)

    for s in sids:
        dsec = dir_start + s.sid // 4
        base = 512 + dsec * SSZ + (s.sid % 4) * 128
        name = s.name.encode("utf-16-le")
        if len(name) > 62:
            name = name[:62]
        img[base:base + len(name)] = name
        struct.pack_into("<H", img, base + 64, len(name) + 2)
        img[base + 66] = s.etype
        struct.pack_into("<I", img, base + 68, s.left)
        struct.pack_into("<I", img, base + 72, s.right)
        struct.pack_into("<I", img, base + 76, s.child)
        struct.pack_into("<I", img, base + 116, s.start if s.etype == 2 else ENDOFCHAIN)
        struct.pack_into("<Q", img, base + 120, s.size if s.etype == 2 else 0)

    for (s, ns) in stream_sectors:
        for i, c in enumerate(s.chain):
            seg = s.data[i * SSZ:]
            off = 512 + c * SSZ
            img[off:off + len(seg)] = seg

    for fi, fsec in enumerate(fat_chain):
        base = 512 + fsec * SSZ
        for j in range(128):
            idx = fi * 128 + j
            v = fat[idx] if idx < total_sectors else FREESECT
            struct.pack_into("<I", img, base + j * 4, v)

    h = img[0:512]
    h[:] = b"\x00" * 512
    img[0:8] = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    struct.pack_into("<H", img, 24, 0x003E)   # minor
    struct.pack_into("<H", img, 26, 3)        # major
    struct.pack_into("<H", img, 28, 0xFFFE)   # byte order
    struct.pack_into("<H", img, 30, 9)        # sector shift -> 512
    struct.pack_into("<H", img, 32, 6)        # mini sector shift -> 64
    struct.pack_into("<I", img, 40, dir_sectors)
    struct.pack_into("<I", img, 44, n_fat)
    struct.pack_into("<I", img, 48, dir_start)
    struct.pack_into("<I", img, 56, 4096)     # mini stream cutoff
    struct.pack_into("<I", img, 60, ENDOFCHAIN)  # first mini FAT
    struct.pack_into("<I", img, 64, 0)        # num mini FAT
    struct.pack_into("<I", img, 68, ENDOFCHAIN)  # first DIFAT
    struct.pack_into("<I", img, 72, 0)        # num DIFAT
    for i in range(109):
        v = fat_chain[i] if i < len(fat_chain) else ENDOFCHAIN
        struct.pack_into("<I", img, 76 + i * 4, v)

    with open(path, "wb") as f:
        f.write(bytes(img))
    return len(sids)
