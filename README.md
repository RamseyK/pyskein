# PySkein

This file only covers some basic installation instructions. For any further
information please consult the docs, starting with "doc/index.html".

## Installation

* Install with Python 3.11 or higher: `python -m pip install pyskein`
* Use included console scripts `skeinsum` or `threefish`, or, `import skein` in your program

### Notes:
    * If you have a version of PySkein <0.5 installed, please make sure to
      manually delete "skein.*" from your Python site-packages directory before
      installing a more recent version!

    * Earlier versions of PySkein may implement different versions of the
      Skein algorithm and so produce different hash outputs.
      Check doc/download.html for an overview of which version of PySkein
      corresponds to which version of the Skein specification.

# Copyright and License Information

Copyright 2008-2013 Hagen Fürstenau
Both the software and the documentation are licensed under GPL version 3.
For the license text see the file "COPYING".
