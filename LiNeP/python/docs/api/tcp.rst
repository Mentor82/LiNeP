linep.tcp
=========

High-level TCP task channel.  :class:`~linep.tcp.Sender` is the client side
(sends TASK, receives RESULT); :class:`~linep.tcp.Receiver` is the server
side (accepts connections, dispatches to a callback).

Both classes support the context-manager protocol and are safe to use from
multiple threads simultaneously.

.. automodule:: linep.tcp
   :members:
   :undoc-members:
   :show-inheritance:
   :member-order: bysource

Task callback signature
-----------------------

The handler passed to :meth:`~linep.tcp.Receiver.start` must have the
following signature:

.. code-block:: python

   def handler(
       task_type:      int,   # one of linep.constants.TaskType
       correlation_id: int,   # echoed in the RESULT header
       worker_id:      int,   # from the inbound TASK header
       slot_id:        int,   # from the inbound TASK header
       payload:        bytes, # raw task body
   ) -> tuple[int, bytes]:    # (ResultStatus, response body)
       ...

The return value ``(status, body)`` is packed into a RESULT frame and sent
back to the client automatically.  Unhandled exceptions inside the handler
are caught and cause a :attr:`~linep.constants.ResultStatus.MODEL_ERROR`
response to be sent.

Thread safety
-------------

* :class:`~linep.tcp.Sender` — fully thread-safe; each :meth:`~linep.tcp.Sender.send_task`
  call opens its own TCP connection.
* :class:`~linep.tcp.Receiver` — :meth:`~linep.tcp.Receiver.start` and
  :meth:`~linep.tcp.Receiver.stop` are protected by an internal lock.
  The user-supplied ``handler`` may be called concurrently from multiple
  worker threads; ensure it is thread-safe.
