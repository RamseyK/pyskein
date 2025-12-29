# -*- encoding: utf-8
import sys
if sys.version_info[:3] < (3, 1):
    print("PySkein requires Python 3.1 or later!\n")
    sys.exit(1)


from distutils.core import setup, Extension


try:
    with open("doc_src/index.rst") as f:
        rst = f.read()
    LONG_DESCRIPTION = rst.split("\n\n", 1)[1].split("\n.. ")[0]
    for ch in ("`", "_", "**"):
        LONG_DESCRIPTION = LONG_DESCRIPTION.replace(ch, "")
except IOError:
    LONG_DESCRIPTION = ""


ext = Extension("_skein",
                sources=["src/threefish.c", "src/_skeinmodule.c"],
                include_dirs=["src"])

setup(name="pyskein",
      version="1.0",
      description="Implementation of the Skein hash function",
      long_description=LONG_DESCRIPTION,
      author="Hagen Fürstenau",
      author_email="hagen at zhuliguan dot net",
      license="GPL",
      url="http://pythonhosted.org/pyskein/",
      classifiers=[
          "Development Status :: 5 - Production/Stable",
          "Intended Audience :: Information Technology",
          "Intended Audience :: Developers",
          "Intended Audience :: Science/Research",
          "License :: OSI Approved :: GNU General Public License (GPL)",
          "Operating System :: OS Independent",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.1",
          "Programming Language :: Python :: 3.2",
          "Programming Language :: Python :: 3.3",
          "Topic :: Security :: Cryptography"],
      package_dir={"": "src"},
      py_modules=["skein"],
      ext_modules=[ext],
      scripts=["scripts/skeinsum"])
