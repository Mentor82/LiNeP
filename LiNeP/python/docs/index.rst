LiNeP — Liara Neural Protocol
==============================

**LiNeP** is a binary networking protocol for distributed AI inference.
Workers announce themselves via compact UDP heartbeats, receive inference
tasks over TCP, and return structured results — all framed with CRC-8
integrity checks and a compact 24-byte header.

This documentation covers the **Python bindings** (:mod:`linep`), which wrap
the native C library via `cffi`_.

.. _cffi: https://cffi.readthedocs.io/

.. toctree::
   :maxdepth: 2
   :caption: Getting started

   installation
   quickstart

.. toctree::
   :maxdepth: 2
   :caption: API reference

   api/index

.. toctree::
   :maxdepth: 1
   :caption: Protocol reference

   protocol/wire_format
   protocol/message_types

Indices
-------

* :ref:`genindex`
* :ref:`modindex`
