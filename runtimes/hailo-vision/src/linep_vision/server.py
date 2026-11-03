"""Loopback-only LiNeP runtime endpoint (the private worker leg, not a trunk)."""

import ipaddress
import logging
import socket
import socketserver
import threading
from dataclasses import dataclass, field

from linep.v0_2.constants import (
    LINEP_V02_HEADER_SIZE, LINEP_V02_MAGIC, LINEP_V02_MAX_PAYLOAD_SIZE,
    ControlType, EnvelopeType, ErrorCategory, EventType, RuntimeProfile, TerminalOutcome, VisionTask,
)
from linep.v0_2.envelopes import (
    CapabilitiesDescriptor, CapabilitiesEnvelope, EventEnvelope, RequestEnvelope, RuntimeErrorPayload,
    decode_capabilities, decode_control, decode_header, decode_request, decode_session_bind,
    encode_capabilities, encode_event,
)
from linep.v0_2.vision import VisionResultPayload
from .detection import VisionError, validate_request

LOG = logging.getLogger(__name__)


@dataclass
class Job:
    stream: object
    lock: object = field(default_factory=threading.Lock)
    cancelled: bool = False
    terminal: bool = False


class VisionServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    # server_close joins connection readers before snapshotting inference workers.
    daemon_threads = False

    def __init__(self, backend, host="127.0.0.1", port=11436, max_clients=8, io_timeout=30.0):
        if not hasattr(RequestEnvelope, "payload_bytes"):
            raise RuntimeError("LiNeP SDK binary-payload fix required (main 10a4854 or later)")
        if not ipaddress.IPv4Address(host).is_loopback:
            raise ValueError("vision runtime must bind an IPv4 loopback address")
        self.backend = backend
        self.models = {d.model_id: d for d in backend.descriptors}
        if not self.models or len(self.models) != len(backend.descriptors):
            raise ValueError("unique, initialized model descriptors required")
        self.io_timeout = io_timeout
        self.slot = threading.Lock()
        self.clients = threading.BoundedSemaphore(max_clients)
        self.guard = threading.Lock()
        self.connections = set()
        self.workers = set()
        self.stopping = threading.Event()
        self.thread = None
        super().__init__((host, port), Handler)

    def process_request(self, request, client_address):
        if self.stopping.is_set() or not self.clients.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.guard:
            self.connections.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.guard:
                self.connections.discard(request)
            self.clients.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.guard:
                self.connections.discard(request)
            self.clients.release()

    def capabilities(self):
        return CapabilitiesEnvelope(descriptor=CapabilitiesDescriptor(
            supported_profiles=[RuntimeProfile.VISION], supported_models=list(self.models),
            supported_vision_models=list(self.models.values()), supports_streaming=False,
            supports_cancellation=True, supports_structured_messages=False,
        ))

    def start(self):
        self.thread = threading.Thread(target=self.serve_forever, daemon=True, name="linep-vision")
        self.thread.start()
        return self

    def stop(self):
        self.stopping.set()
        if self.thread is not None:
            self.shutdown()
            self.thread.join()
        with self.guard:
            connections = list(self.connections)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.server_close()
        # Hardware calls have bounded VStream timeouts. Never destroy the backend
        # underneath an inference still using it.
        with self.guard:
            workers = list(self.workers)
        for worker in workers:
            worker.join(timeout=12)
        if any(worker.is_alive() for worker in workers):
            raise RuntimeError("Hailo inference did not stop; backend remains owned by worker")


class Handler(socketserver.BaseRequestHandler):
    def setup(self):
        self.request.settimeout(self.server.io_timeout)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.send_lock = threading.Lock()
        self.active = None
        self.state_lock = threading.Lock()
        self.dead = threading.Event()

    def exact(self, count):
        data = bytearray()
        while len(data) < count:
            chunk = self.request.recv(count - len(data))
            if not chunk:
                raise EOFError()
            data.extend(chunk)
        return bytes(data)

    def send(self, frame):
        with self.send_lock:
            if self.dead.is_set():
                raise EOFError()
            self.request.sendall(frame)

    def fail(self, stream, error, seq=1):
        self.send(encode_event(EventEnvelope(
            stream=stream, event_seq=seq, event_type=EventType.FAILED,
            outcome=TerminalOutcome.FAILED,
            error=RuntimeErrorPayload(category=error.category, code=error.code, message=str(error)),
        )))

    def handle(self):
        try:
            while not self.server.stopping.is_set():
                header = self.exact(LINEP_V02_HEADER_SIZE)
                hdr = decode_header(header)
                if (hdr is None or hdr.magic != LINEP_V02_MAGIC
                        or (hdr.version_major, hdr.version_minor) != (0, 2)
                        or hdr.flags != 0 or hdr.payload_len > LINEP_V02_MAX_PAYLOAD_SIZE):
                    return
                frame = header + self.exact(hdr.payload_len)
                if hdr.envelope_type == int(EnvelopeType.CAPABILITIES):
                    if decode_capabilities(frame) is None:
                        return
                    self.send(encode_capabilities(self.server.capabilities()))
                elif hdr.envelope_type == int(EnvelopeType.SESSION_BIND):
                    # Syntactic compatibility only. Client leases and SL1 are
                    # enforced by linepd, not by this private loopback endpoint.
                    if decode_session_bind(frame) is None:
                        return
                elif hdr.envelope_type == int(EnvelopeType.CONTROL):
                    ctrl = decode_control(frame)
                    if ctrl is None:
                        return
                    if ctrl.control_type == ControlType.CANCEL:
                        with self.state_lock:
                            job = self.active
                        if job is not None and job.stream == ctrl.stream:
                            with job.lock:
                                if not job.terminal:
                                    job.cancelled = True
                elif hdr.envelope_type == int(EnvelopeType.REQUEST):
                    req = decode_request(frame)
                    if req is None:
                        return
                    with self.state_lock:
                        job = self.active
                    if job is not None:
                        with job.lock:
                            if not job.terminal:
                                if job.stream == req.stream:
                                    # Reusing an active identity cannot yield a second terminal.
                                    return
                                self.fail(req.stream, VisionError("VISION_BUSY", ErrorCategory.RESOURCE_EXHAUSTED, 429))
                                continue
                    try:
                        options = validate_request(req, self.server.models)
                    except VisionError as error:
                        self.fail(req.stream, error)
                        continue
                    if not self.server.slot.acquire(blocking=False):
                        self.fail(req.stream, VisionError("VISION_BUSY", ErrorCategory.RESOURCE_EXHAUSTED, 429))
                        continue
                    job = Job(req.stream)
                    with self.state_lock:
                        self.active = job
                    worker = threading.Thread(target=self.execute, args=(req, options, job), daemon=True)
                    with self.server.guard:
                        self.server.workers.add(worker)
                        # Starting under the guard makes shutdown's snapshot safe.
                        worker.start()
                else:
                    return
        except (OSError, EOFError):
            pass
        except Exception:
            LOG.exception("vision connection failed")

    def execute(self, req, options, job):
        seq = 1
        slot_owned = True
        try:
            with job.lock:
                self.send(encode_event(EventEnvelope(stream=req.stream, event_seq=seq, event_type=EventType.ACCEPTED)))
            seq += 1
            result = self.server.backend.detect(req.model_id, req.payload, options)
            if not result.is_valid():
                raise VisionError("VISION_INVALID_MODEL_OUTPUT", ErrorCategory.MODEL_ERROR, 502)
            self.server.slot.release()
            slot_owned = False
            with job.lock:
                if job.cancelled:
                    self.send(encode_event(EventEnvelope(
                        stream=req.stream, event_seq=seq, event_type=EventType.CANCELLED,
                        outcome=TerminalOutcome.CANCELLED)))
                else:
                    model = self.server.models[req.model_id]
                    self.send(encode_event(EventEnvelope(
                        stream=req.stream, event_seq=seq, event_type=EventType.VISION_RESULT,
                        vision=VisionResultPayload(VisionTask.DETECT, req.model_id, model.model_revision, result))))
                    seq += 1
                    self.send(encode_event(EventEnvelope(
                        stream=req.stream, event_seq=seq, event_type=EventType.COMPLETED,
                        outcome=TerminalOutcome.COMPLETED)))
                job.terminal = True
        except (OSError, EOFError):
            self.dead.set()
            try:
                self.request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        except Exception as exc:
            if slot_owned:
                self.server.slot.release()
                slot_owned = False
            error = exc if isinstance(exc, VisionError) else VisionError("VISION_BACKEND_FAILED", ErrorCategory.MODEL_ERROR, 502)
            if error.category in (ErrorCategory.MODEL_ERROR, ErrorCategory.INTERNAL):
                LOG.exception("vision inference failed for model %s", req.model_id)
            else:
                LOG.info("vision request failed for model %s: %s", req.model_id, error)
            try:
                with job.lock:
                    if not job.terminal:
                        self.fail(req.stream, error, seq)
                        job.terminal = True
            except (OSError, EOFError):
                self.dead.set()
        finally:
            with self.state_lock:
                if self.active is job:
                    self.active = None
            if slot_owned:
                self.server.slot.release()
            with self.server.guard:
                self.server.workers.discard(threading.current_thread())

    def finish(self):
        self.dead.set()
        with self.state_lock:
            job = self.active
        if job is not None:
            with job.lock:
                job.cancelled = True
