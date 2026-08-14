linep.framing
=============

Python dataclasses that mirror the packed C structs used on the wire.
All ``build()`` class-methods delegate to the C library to compute CRC-8
values, so the resulting objects are always wire-correct.

.. automodule:: linep.framing
   :members:
   :undoc-members:
   :show-inheritance:
   :member-order: bysource

Wire layout — Header (24 bytes)
--------------------------------

.. code-block:: text

   Offset  Size  Field
   ──────  ────  ─────────────────────────────────────────────────────
        0     2  magic          0x4C4E ("LN")
        2     1  version        0x01
        3     1  msg_type       linep.constants.MsgType
        4     2  header_len     24 (base) / 30 (with BuildTimeExt)
        6     2  flags          linep.constants.HeaderFlags bitmask
        8     4  payload_len    bytes after the full header
       12     4  sequence       monotone sender counter
       16     4  correlation_id request/response correlation token
       20     2  worker_id
       22     1  slot_id
       23     1  header_crc     CRC-8 over bytes 0–22

Optional v1.1 BuildTimeExt (6 bytes, appended when FLAG_BUILD_TIME is set)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   Offset  Size  Field
   ──────  ────  ────────────────────────────────────
       24     1  year_2d   years since 2000 (e.g. 26)
       25     1  month     1–12
       26     1  day       1–31
       27     1  hour      0–23
       28     1  minute    0–59
       29     1  second    0–59

Wire layout — HeartbeatCompact (12 bytes, UDP)
----------------------------------------------

.. code-block:: text

   Offset  Size  Field
   ──────  ────  ────────────────────────────────────────────────────
        0     2  magic          0x4C4E
        2     1  version        0x01
        3     1  msg_type       0x01 (HEARTBEAT)
        4     2  worker_id
        6     1  slot_id
        7     1  slot_flags     linep.constants.SlotFlags bitmask
        8     1  load           0-100 %, 200=unknown, 250=offline
        9     1  queue_depth    0–254, 255=overflow
       10     1  sequence       wraps at 255
       11     1  crc8           CRC-8 over bytes 0–10
