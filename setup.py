#!/usr/bin/env python3

from setuptools import Extension, setup

ext = Extension("_skein", sources=["pyskein/threefish.c", "pyskein/_skeinmodule.c"], include_dirs=["pyskein"])
setup(ext_modules=[ext])
