"""
linep.scoring
-------------
Pure-Python slot scoring helpers — parity with ``score_engine.cpp`` V0.1.0.

These functions are useful for Python-side coworker health monitoring, test
assertions, and offline analysis without crossing the C ABI boundary.

All weight constants are intentionally kept as module-level literals so that
downstream code can import and verify them independently of the C++ sources.

Scoring formula (V0.1.0 baseline)::

    scheduler_score = load * 1.0 + queue_depth * 10.0
    worker_score_f  = worker_score * 0.1          # uint16 → float
    s               = 0.35 * worker_score_f + 0.65 * scheduler_score
    s              += avg_latency_ms * 0.02
    s              += 20.0   if busy
    s              += 50.0   if degraded
    s              += 100.0  if thermal_limit
    s              += timeout_count * 15.0
    s              += error_count   * 25.0

Lower score → more preferred.  Only call :func:`score_slot` for eligible slots.
"""

from __future__ import annotations

__all__ = [
    # Weight constants (mirrors score_engine.cpp V0.1.0)
    "W_WORKER_SCORE",
    "W_SCHEDULER_SCORE",
    "W_WORKER_SCORE_SCALE",
    "W_LATENCY",
    "PENALTY_BUSY",
    "PENALTY_DEGRADED",
    "PENALTY_THERMAL",
    "PENALTY_TIMEOUT",
    "PENALTY_ERROR",
    # Main API
    "score_slot",
    "compute_worker_score",
]

# ── Weight constants ──────────────────────────────────────────────────────────
# Keep these in sync with src/scheduler/score_engine.cpp.

W_WORKER_SCORE: float = 0.35
"""Blend weight for the coworker-reported worker_score component."""

W_SCHEDULER_SCORE: float = 0.65
"""Blend weight for the scheduler-side load estimate component."""

W_WORKER_SCORE_SCALE: float = 0.1
"""Scale factor applied to raw uint16 worker_score before blending."""

W_LATENCY: float = 0.02
"""Per-millisecond latency penalty applied to the blended score."""

PENALTY_BUSY: float = 20.0
"""Score penalty added when the slot is busy."""

PENALTY_DEGRADED: float = 50.0
"""Score penalty added when the slot is in degraded mode."""

PENALTY_THERMAL: float = 100.0
"""Score penalty added when the slot is thermal-limited."""

PENALTY_TIMEOUT: float = 15.0
"""Score penalty per accumulated timeout."""

PENALTY_ERROR: float = 25.0
"""Score penalty per accumulated error."""


# ── score_slot ────────────────────────────────────────────────────────────────

def score_slot(
    *,
    load: int,
    queue_depth: int,
    worker_score: int,
    avg_latency_ms: float = 0.0,
    busy: bool = False,
    degraded: bool = False,
    thermal_limit: bool = False,
    timeout_count: int = 0,
    error_count: int = 0,
) -> float:
    """Compute the scheduler score for a single slot.

    Parameters mirror the fields of ``SlotState`` in ``slot_registry.hpp``.
    All inputs are validated at the boundary; values outside the expected
    ranges are clamped rather than raising so that malformed telemetry does not
    crash the caller.

    Parameters
    ----------
    load:
        Current CPU/GPU load percentage (0–100).  Values outside [0, 100] are
        clamped.
    queue_depth:
        Number of tasks queued at the slot (0–255).
    worker_score:
        Raw ``uint16`` worker_score as reported in the heartbeat frame.
    avg_latency_ms:
        Exponential moving average of inference latency in milliseconds.
        Must be ≥ 0; negative values are treated as 0.
    busy:
        Slot is actively processing a task.
    degraded:
        Slot is running in degraded mode (reduced capacity / accuracy).
    thermal_limit:
        Slot is throttled due to thermal constraints.
    timeout_count:
        Cumulative number of tasks that timed out on this slot.
    error_count:
        Cumulative number of hard errors on this slot.

    Returns
    -------
    float
        Blended score.  Lower is better.  Only meaningful for eligible slots.
    """
    load         = max(0, min(100, load))
    queue_depth  = max(0, min(255, queue_depth))
    worker_score = max(0, min(0xFFFF, worker_score))
    avg_latency_ms = max(0.0, avg_latency_ms)

    scheduler_score = load * 1.0 + queue_depth * 10.0
    worker_score_f  = worker_score * W_WORKER_SCORE_SCALE

    s = W_WORKER_SCORE * worker_score_f + W_SCHEDULER_SCORE * scheduler_score
    s += avg_latency_ms * W_LATENCY
    if busy:          s += PENALTY_BUSY
    if degraded:      s += PENALTY_DEGRADED
    if thermal_limit: s += PENALTY_THERMAL
    s += timeout_count * PENALTY_TIMEOUT
    s += error_count   * PENALTY_ERROR
    return s


# ── compute_worker_score ──────────────────────────────────────────────────────

def compute_worker_score(
    *,
    load: int,
    queue_depth: int,
    error_rate: float = 0.0,
    thermal_limit: bool = False,
) -> int:
    """Compute a ``uint16`` worker_score suitable for the heartbeat frame.

    This is the canonical Python-side formula for a coworker to self-report
    its health as a compact score.  The scheduler on the other end will blend
    this value into the slot selection score via :func:`score_slot`.

    Formula::

        raw = load * 1.0
            + queue_depth * 8.0
            + error_rate  * 200.0   (error_rate in [0.0, 1.0])
            + 300.0                  if thermal_limit
        return clamp(round(raw), 0, 65535)

    Parameters
    ----------
    load:
        Current load percentage (0–100).
    queue_depth:
        Number of tasks queued at the slot (0–255).
    error_rate:
        Recent error rate as a fraction in [0.0, 1.0].
    thermal_limit:
        Whether the slot is currently thermal-throttled.

    Returns
    -------
    int
        A ``uint16`` worker_score in [0, 65535].
    """
    load        = max(0, min(100, load))
    queue_depth = max(0, min(255, queue_depth))
    error_rate  = max(0.0, min(1.0, error_rate))

    raw  = load * 1.0
    raw += queue_depth * 8.0
    raw += error_rate  * 200.0
    if thermal_limit:
        raw += 300.0
    return max(0, min(0xFFFF, round(raw)))
