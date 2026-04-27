#!/usr/bin/env python3

import sys

from setuptools import Extension, setup

if sys.platform == "win32":
    extra_compile_args = [
        "/O2",
        "/std:c11",
        # Stack canaries/buffer security checks
        "/GS",
        # Warnings
        "/W4",
        # Do not use language/MSVC extensions
        "/permissive-"
    ]
else:
    extra_compile_args = [
        # "-O0", "-g",  # debug
        "-O2",  # release
        "-std=c11",
        "-fstack-protector-all",
        # Warnings
        "-Wall", "-Wextra", "-Wno-sign-compare",
        "-Wno-missing-field-initializers", "-Wformat", "-Wformat=2",
        "-Wimplicit-fallthrough",
        # Position-independent
        "-fPIE",
        "-fno-delete-null-pointer-checks",
        "-fno-strict-aliasing",
        # Do not use language extensions
        "-pedantic"
    ]

ext = Extension("_skein",
                sources=["skein/threefish.c", "skein/_skeinmodule.c"],
                include_dirs=["skein"],
                extra_compile_args=extra_compile_args,
                extra_link_args=[])
setup(ext_modules=[ext])
