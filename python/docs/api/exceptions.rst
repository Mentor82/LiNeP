linep.exceptions
================

All exceptions raised by the LiNeP Python bindings are subclasses of
:exc:`LiNePError`, so callers can catch everything with a single clause::

   try:
       result = sender.send_task(...)
   except linep.LiNePError as exc:
       print(f"error {exc.code}: {exc}")

Or handle specific failure modes::

   from linep.exceptions import TimeoutError, ConnectError

   try:
       result = sender.send_task(...)
   except TimeoutError:
       reschedule()
   except ConnectError:
       mark_worker_offline()

.. automodule:: linep.exceptions
   :members:
   :undoc-members:
   :show-inheritance:
   :member-order: bysource

Error-code mapping
------------------

.. list-table::
   :header-rows: 1
   :widths: 15 15 70

   * - C constant
     - Value
     - Python exception
   * - ``LINEP_C_OK``
     - ``0``
     - *(no exception)*
   * - ``LINEP_C_ERR_ARG``
     - ``-1``
     - :exc:`ArgumentError`
   * - ``LINEP_C_ERR_TIMEOUT``
     - ``-2``
     - :exc:`TimeoutError`
   * - ``LINEP_C_ERR_CONNECT``
     - ``-3``
     - :exc:`ConnectError`
   * - ``LINEP_C_ERR_SEND``
     - ``-4``
     - :exc:`SendError`
   * - ``LINEP_C_ERR_RECV``
     - ``-5``
     - :exc:`RecvError`
   * - ``LINEP_C_ERR_BAD_FRAME``
     - ``-6``
     - :exc:`BadFrameError`
   * - ``LINEP_C_ERR_PORT``
     - ``-7``
     - :exc:`PortError`
   * - ``LINEP_C_ERR_INTERNAL``
     - ``-8``
     - :exc:`InternalError`
   * - ``LINEP_C_ERR_BUF_SMALL``
     - ``-9``
     - :exc:`BufferTooSmallError`
