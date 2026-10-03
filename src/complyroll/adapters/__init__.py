"""Source adapters and hardened ingestion entry points."""

from .base import (
    AdapterOutput,
    ArtifactProvenance,
    ControlMapping,
    DiagnosticLevel,
    IngestDiagnostic,
    IngestResult,
    SourceAdapter,
)
from .failures import (
    DETECTION_FAILURE_SOURCE_TYPE,
    FAILURE_DIAGNOSTIC_CAP,
    FailureClass,
    FailureClassification,
    UnmintableReason,
    classify_ingest,
    failure_diagnostics,
    system_observation_for,
)
from .hdf import HDF_PARSER_VERSION, HdfAdapter
from .safeio import DEFAULT_LIMITS, IngestLimits, InputLimitError, UnsafeXmlError
from .sarif import SARIF_PARSER_VERSION, SarifAdapter
from .stig import (
    CciControlMap,
    CciMapResult,
    CklAdapter,
    CklbAdapter,
    XccdfAdapter,
    ingest_stig_artifact,
    load_cci_control_map,
)

__all__ = [
    "AdapterOutput",
    "ArtifactProvenance",
    "CciControlMap",
    "CciMapResult",
    "CklAdapter",
    "CklbAdapter",
    "ControlMapping",
    "DEFAULT_LIMITS",
    "DETECTION_FAILURE_SOURCE_TYPE",
    "DiagnosticLevel",
    "FAILURE_DIAGNOSTIC_CAP",
    "FailureClass",
    "FailureClassification",
    "HDF_PARSER_VERSION",
    "HdfAdapter",
    "IngestDiagnostic",
    "IngestLimits",
    "IngestResult",
    "InputLimitError",
    "SARIF_PARSER_VERSION",
    "SarifAdapter",
    "SourceAdapter",
    "UnmintableReason",
    "UnsafeXmlError",
    "XccdfAdapter",
    "classify_ingest",
    "failure_diagnostics",
    "ingest_stig_artifact",
    "load_cci_control_map",
    "system_observation_for",
]
