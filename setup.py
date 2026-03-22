#!/usr/bin/env python3

import platform
from setuptools import Extension, setup

extra_compile_args = [
    "-O0", "-g",  # debug
    "-std=c11",
    "-fstack-protector-all",
    # Warnings
    "-Wall", "-Wextra", "-Wno-sign-compare",
    "-Wno-missing-field-initializers", "-Wformat", "-Wformat=2",
    "-Wimplicit-fallthrough",
    # Position-independent
    "-fPIE",
    # NULL pointers must not be treated as undefined behavior
    "-fno-delete-null-pointer-checks",

    "-fno-strict-aliasing",
    # Do not use language extensions
    "-pedantic"
]

# Memory accesses *must* be aligned for arm64
if platform.machine() in ("arm64", "aarch64"):
    extra_compile_args.append("-mstrict-align")

ext = Extension("_skein",
                sources=["skein/threefish.c", "skein/_skeinmodule.c"],
                include_dirs=["skein"],
                extra_compiler_args=extra_compile_args,
                extra_link_args=[])
setup(ext_modules=[ext])
