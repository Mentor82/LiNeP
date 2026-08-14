Wire Format
===========

All multi-byte integer fields are **little-endian** (host byte order on
x86/ARM64).  Big-endian peers are not supported in protocol version 1.

Byte order marker
-----------------

The header byte at offset 6 bit-field reserved area carries an implicit
little-endian assumption.  A dedicated ``WIRE_BYTE_ORDER`` constant
(``0x01`` = LE) is stored in the library but not transmitted; both sides
must agree on the endianness out of band.

Frame structure
---------------

Every TCP frame consists of:

.. code-block:: text

   ┌────────────────────────────────────────┐
   │  Header  (24 bytes, always present)    │
   ├────────────────────────────────────────┤
   │  BuildTimeExt  (6 bytes, v1.1 only,    │
   │  present when FLAG_BUILD_TIME is set)  │
   ├────────────────────────────────────────┤
   │  Payload  (payload_len bytes)          │
   └────────────────────────────────────────┘

UDP frames carry only the 12-byte :class:`~linep.framing.HeartbeatCompact`
struct.

Payload limits
--------------

Frames with ``payload_len`` > 4 MiB (4 × 2²⁰ bytes) are rejected by the
receiver to guard against allocation-exhaustion attacks.

CRC-8
-----

* Polynomial: ``0x07`` (CRC-8/SMBUS)
* Initial value: ``0x00``
* Reflection: none

The CRC byte in **Header** (``header_crc``) is computed over bytes 0–22 of
the packed header struct.

The CRC byte in **HeartbeatCompact** (``crc8``) is computed over bytes 0–10
of the packed heartbeat struct.

The library exposes this algorithm as :func:`linep.crc8`.

Magic bytes
-----------

Both frame types begin with the 16-bit magic value ``0x4C4E`` (ASCII
``"LN"``).  Any receiver that sees a different value must discard the frame
immediately without further parsing.

Fragmentation
-------------

Large payloads may be split into multiple frames by setting
:attr:`~linep.constants.HeaderFlags.FRAGMENTED` on all but the last fragment
and :attr:`~linep.constants.HeaderFlags.FINAL_FRAGMENT` on the last one.
The same ``correlation_id`` ties all fragments together.

.. note::
   Fragment reassembly is not implemented in protocol version 1.  The flags
   are reserved for future use.
