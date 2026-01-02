import timeit

COUNT = 10
BLOCK_SIZE = 10  # MB


def hashing_throughput(module, func, args=""):
    """Return performance in MB/s"""
    setup = f"from {module} import {func} as hasher; update = hasher({args}).update; "\
            f"txt = bytes({BLOCK_SIZE*2**20})"
    best = min(timeit.repeat("update(txt)", setup, number=COUNT, repeat=5))
    return COUNT * BLOCK_SIZE / best


if __name__ == "__main__":
    hashers = [("hashlib", f) for f in ("md5", "sha1", "sha256", "sha512")]
    hashers += [("skein", f) for f in ("skein256", "skein512", "skein1024")]
    for module, func in hashers:
        x = hashing_throughput(module, func)
        print(f"{module}.{func}: {x:.0f} MB/s")
    x = hashing_throughput("skein", "skein512", "tree=(10,10,255)")
    print(f"skein.skein512 [tree=(10,10,255)]: {x:.0f} MB/s")
