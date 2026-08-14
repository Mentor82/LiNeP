Quick start
===========

This guide shows the most common usage patterns.  See the :doc:`api/index`
for full API documentation.

Two-port setup
--------------

LiNeP uses two different ports:

* ``tcp_port`` for TASK/RESULT traffic (TCP)
* ``udp_port`` for HEARTBEAT traffic (UDP)

Use :class:`linep.PortPair` to model this explicitly::

    import linep

    ports = linep.PortPair(tcp_port=9000, udp_port=9001)

Doctor (DLL + TCP + UDP)
-------------------------

The package installs a ``linep-doctor`` command that validates your local
setup and both protocol ports.

Run all checks::

    linep-doctor --host 127.0.0.1 --tcp-port 9000 --udp-port 9001

Use explicit shared-library path when needed::

    linep-doctor --lib C:\\ai\\LiNeP\\build\\liblinep.dll

Skip one transport temporarily::

    linep-doctor --skip-tcp
    linep-doctor --skip-udp

Setup
-----

Import the package and initialise the network layer::

   import linep

   linep.net_init()   # WSAStartup on Windows, no-op on POSIX

Always call :func:`linep.net_cleanup` when you're done::

   linep.net_cleanup()

Or use a ``try/finally`` block::

   linep.net_init()
   try:
       ...
   finally:
       linep.net_cleanup()


Sending an inference task
--------------------------

Use :class:`linep.tcp.Sender` to send a task to a worker and receive the
result.  The :class:`~linep.tcp.Sender` supports the context-manager
protocol::

   from linep import TaskType, ResultStatus
   import linep.tcp

   linep.net_init()

   with linep.tcp.Sender() as sender:
       result = sender.send_task(
           host="127.0.0.1",
           port=9000,
           task_type=TaskType.INSTRUCT,
           payload=b"What is the capital of France?",
           correlation_id=1,
           worker_id=1,
           slot_id=0,
           timeout_ms=10_000,
       )

   if result.status == ResultStatus.OK:
       print(result.text)
   else:
       print(f"Worker error: {result.status.name}")

   linep.net_cleanup()

Raising on non-OK status
~~~~~~~~~~~~~~~~~~~~~~~~

:meth:`~linep.tcp.TaskResult.raise_on_error` converts a non-OK status into a
:exc:`~linep.exceptions.LiNePError`::

   result.raise_on_error()   # raises if status != OK


Serving inference tasks
-----------------------

Use :class:`linep.tcp.Receiver` to implement a worker node.  Your handler
receives the raw task bytes and returns ``(status, body)``::

   import time
   import linep
   import linep.tcp
   from linep.constants import ResultStatus, TaskType

   def my_handler(task_type, correlation_id, worker_id, slot_id, payload):
       prompt = payload.decode("utf-8", errors="replace")
       # --- call your model here ---
       answer = f"Echo: {prompt}"
       return ResultStatus.OK, answer.encode()

   linep.net_init()

   with linep.tcp.Receiver() as recv:
       recv.start(port=9000, handler=my_handler)
       print("Worker listening on :9000 — press Ctrl-C to stop")
       try:
           while True:
               time.sleep(1)
       except KeyboardInterrupt:
           pass

   linep.net_cleanup()


Working with frames directly
-----------------------------

Build and inspect a :class:`~linep.framing.Header`::

   from linep.framing import Header
   from linep.constants import MsgType

   h = Header.build(
       msg_type=MsgType.TASK,
       payload_len=128,
       sequence=1,
       correlation_id=42,
       worker_id=3,
       slot_id=0,
   )
   h.validate()          # raises BadFrameError on CRC mismatch
   raw = h.to_bytes()    # 24 bytes, ready to write to a socket

Decode a received heartbeat over UDP::

   from linep.framing import HeartbeatCompact
   from linep.constants import SlotFlags

   # raw_bytes comes from socket.recvfrom(...)
   hb = HeartbeatCompact.from_bytes(raw_bytes)
   hb.validate()

   if hb.is_ready:
       print(f"Worker {hb.worker_id} slot {hb.slot_id} is ready, load={hb.load}%")
   if hb.slot_flags & SlotFlags.THERMAL_LIMIT:
       print("⚠ thermal throttling active")


Computing CRC-8
---------------

The same CRC-8 (poly ``0x07``) used to protect wire frames is available as a
standalone function::

   import linep

   digest = linep.crc8(b"hello")
   print(hex(digest))   # e.g. 0x92


Error handling
--------------

All errors raised by this library are subclasses of
:exc:`~linep.exceptions.LiNePError`::

   from linep.exceptions import LiNePError, TimeoutError

   try:
       result = sender.send_task(...)
   except TimeoutError:
       print("worker did not respond in time")
   except LiNePError as exc:
       print(f"protocol error {exc.code}: {exc}")
