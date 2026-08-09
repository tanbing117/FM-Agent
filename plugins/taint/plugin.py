"""Taint plugin: FM-Agent stage hook entry points.

Stage 1/5 are shared with the IFC plugin — same artifact contract, different
semantic analysis in Stage 6.
"""

from plugins.ifc.stage1 import replace_generate_phase_plan  # noqa: F401
from plugins.ifc.stage5 import replace_generate_topdown_layers  # noqa: F401
from plugins.taint.stage6 import replace_generate_specs_and_verification  # noqa: F401
