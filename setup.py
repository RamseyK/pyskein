#!/usr/bin/env python3

from setuptools import Extension, setup

ext = Extension("_skein", sources=["skein/threefish.c", "skein/_skeinmodule.c"], include_dirs=["skein"])
setup(ext_modules=[ext])
