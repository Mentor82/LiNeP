Installation
============

Requirements
------------

* Python 3.9 or later
* ``cffi`` ≥ 1.15  (installed automatically as a dependency)
* The compiled LiNeP shared library:

  * **Windows** — ``linep.dll``
  * **Linux**   — ``liblinep.so.1``
  * **macOS**   — ``liblinep.dylib``

Building the shared library
---------------------------

Clone the repository and run CMake.  A C++17 compiler and CMake ≥ 3.20 are
required.

.. code-block:: bash

   git clone https://github.com/your-org/LiNeP.git
   cd LiNeP
   cmake -S . -B build -DLINEP_BUILD_SHARED=ON -DLINEP_BUILD_TESTS=OFF
   cmake --build build --target linep

The resulting ``build/liblinep.dll`` (Windows) or ``build/liblinep.so``
(Linux) must be reachable by the Python binding.

Installing the Python package
------------------------------

**Development install** (from the repository)::

   cd LiNeP/python
   pip install -e .

**From a wheel** (when a pre-built wheel is available)::

   pip install linep-1.0.0-py3-none-any.whl

Making the shared library discoverable
---------------------------------------

The Python package searches for the shared library in this order:

1. The path given in the ``LINEP_LIB_PATH`` environment variable
   (e.g. ``export LINEP_LIB_PATH=/opt/linep/liblinep.so.1``).
2. The directory of the installed Python package itself — so you can copy the
   ``.dll`` / ``.so`` next to the ``linep/`` folder.
3. The standard OS library search path (``PATH`` on Windows,
   ``LD_LIBRARY_PATH`` on Linux, ``DYLD_LIBRARY_PATH`` on macOS).

Tip: for quick local testing you can set the environment variable::

   # Linux / macOS
   export LINEP_LIB_PATH=/path/to/LiNeP/build/liblinep.so.1

   # Windows PowerShell
   $env:LINEP_LIB_PATH = "C:\ai\LiNeP\build\liblinep.dll"

Optional extras
---------------

Install the documentation build dependencies::

   pip install "linep[docs]"

Install the development and test dependencies::

   pip install "linep[dev]"
