#!/usr/bin/env python3

#   skeinsum
#   Copyright 2008, 2009 Hagen Fürstenau <hagen@zhuliguan.net>
#
#   Demonstrates Skein hashing with PySkein.
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
from io import DEFAULT_BUFFER_SIZE

import skein

HASH = skein.skein512
DIGEST_BITS = 256


def printsum(f, name):
    h = HASH(digest_bits=DIGEST_BITS)
    buf = True
    while buf:
        try:
            buf = f.read(DEFAULT_BUFFER_SIZE)
        except KeyboardInterrupt:
            print()
            sys.exit(130)
        h.update(buf)
    try:
        print(f"{h.hexdigest()}  {name}")
    except OSError as e:
        if e.errno != 32:
            raise


def main():
    if len(sys.argv) < 2:
        printsum(sys.stdin.buffer, "-")
    else:
        for filename in sys.argv[1:]:
            if os.path.isdir(filename):
                print(f"skeinsum: {filename}: is a directory", file=sys.stderr)
                continue
            with open(filename, "rb") as f:
                printsum(f, filename)
    return 0


if __name__ == "__main__":
    sys.exit(main())
