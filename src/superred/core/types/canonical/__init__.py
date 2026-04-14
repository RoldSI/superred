"""Target self-description metadata.

This subpackage previously hosted a parallel canonical type system
(``TraceEvent``, ``InterfaceSpec``, ``ThreatModel``, projection helpers)
intended for cross-target normalization. That layer overlapped with
the framework's existing :class:`~superred.core.types.trajectory.Trajectory`
and :class:`~superred.core.types.controllable.Controllable` /
:class:`~superred.core.types.observable.Observable` surfaces.

Targets now emit native activity directly through the trajectory as
:class:`~superred.core.types.events.ObservableEvent` s and describe
their surfaces via the existing controllable/observable specs. The
only survivor is :class:`TargetMetadata`, a thin self-description
record used by adapter discovery that has no counterpart elsewhere
in the framework.
"""

from superred.core.types.canonical.target_metadata import TargetMetadata

__all__ = ["TargetMetadata"]
