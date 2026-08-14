Message Types
=============

Every LiNeP frame carries a one-byte ``msg_type`` field in the header.
The full set of message types is defined in
:class:`~linep.constants.MsgType`.

Presence
--------

.. list-table::
   :header-rows: 1
   :widths: 8 15 77

   * - Byte
     - Name
     - Description
   * - ``0x01``
     - HEARTBEAT
     - Compact 12-byte UDP broadcast from worker to scheduler.
       Uses :class:`~linep.framing.HeartbeatCompact` rather than the
       standard header.
   * - ``0x02``
     - REGISTER
     - Worker registers with the scheduler over TCP.
   * - ``0x03``
     - REGISTER_ACK
     - Scheduler acknowledges a REGISTER frame.
   * - ``0x04``
     - BYE
     - Worker is shutting down gracefully.

Inference
---------

.. list-table::
   :header-rows: 1
   :widths: 8 15 77

   * - Byte
     - Name
     - Description
   * - ``0x10``
     - TASK
     - Scheduler sends an inference task to a worker.
       Payload: ``task_type`` byte + raw prompt/input body.
   * - ``0x11``
     - TASK_ACK
     - Worker confirms receipt of a TASK frame.
   * - ``0x12``
     - RESULT
     - Worker returns the inference result.
       Payload byte 0: :class:`~linep.constants.ResultStatus`.
       Bytes 1–N: UTF-8 response body (JSON).
   * - ``0x13``
     - MSG_ERROR
     - Worker or scheduler reports a protocol or model error.
       Payload bytes 0–1: :class:`~linep.constants.ErrorCode` (uint16 LE).
       Bytes 2–N: human-readable reason string (UTF-8, optional).

Status
------

.. list-table::
   :header-rows: 1
   :widths: 8 15 77

   * - Byte
     - Name
     - Description
   * - ``0x20``
     - STATUS_REQUEST
     - Request slot status from a worker.
   * - ``0x21``
     - STATUS_RESPONSE
     - Worker's response to a status request.

Embedding
---------

.. list-table::
   :header-rows: 1
   :widths: 8 15 77

   * - Byte
     - Name
     - Description
   * - ``0x30``
     - EMBED_REQUEST
     - Request text embeddings from a worker.
   * - ``0x31``
     - EMBED_RESPONSE
     - Worker returns embedding vector.
   * - ``0x32``
     - SIMILARITY_REQUEST
     - Request cosine-similarity score between two texts.
   * - ``0x33``
     - SIMILARITY_RESPONSE
     - Worker returns similarity score.

Consensus
---------

.. list-table::
   :header-rows: 1
   :widths: 8 15 77

   * - Byte
     - Name
     - Description
   * - ``0x40``
     - CONSENSUS_REQUEST
     - Scheduler initiates a multi-worker consensus round.
   * - ``0x41``
     - CONSENSUS_RESPONSE
     - Worker returns its vote for the consensus.

Diagnostics
-----------

.. list-table::
   :header-rows: 1
   :widths: 8 15 77

   * - Byte
     - Name
     - Description
   * - ``0xF0``
     - PING
     - Liveness probe sent to a worker.
   * - ``0xF1``
     - PONG
     - Worker response to a PING.

Task types
----------

The ``task_type`` byte in TASK / REGISTER frames selects the inference
pipeline on the worker:

.. list-table::
   :header-rows: 1
   :widths: 8 20 72

   * - Byte
     - Name
     - Description
   * - ``0x01``
     - INSTRUCT
     - Instruction-following / chat completion.
   * - ``0x02``
     - CODE
     - Code generation or completion.
   * - ``0x03``
     - SUMMARIZE
     - Text summarisation.
   * - ``0x04``
     - CLASSIFY
     - Classification / labelling.
   * - ``0x05``
     - VALIDATE
     - Output validation / scoring.
   * - ``0x06``
     - EDGE_TEXT_EVAL
     - Lightweight on-device text evaluation.

RESULT payload schema
----------------------

Byte 0 is always a :class:`~linep.constants.ResultStatus` byte.  Bytes 1–N
carry a UTF-8 JSON body:

.. code-block:: json

   {
     "text":       "<generated text>",
     "model":      "<model name>",
     "tokens_in":  1234,
     "tokens_out": 567,
     "latency_ms": 890
   }

Callers must tolerate missing fields (default: ``0`` / empty string) to
remain forward-compatible with older workers.
