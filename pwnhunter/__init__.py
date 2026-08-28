"""PwnHunter deterministic vulnerability-candidate scanner."""

from .engine import Analyzer
from .ir import (
    Assignment,
    BasicBlock,
    BufferInfo,
    Call,
    Expr,
    Finding,
    FunctionIR,
    Condition,
    Return,
    Severity,
    StackSlot,
)
from .summaries import FunctionSummary, SummaryBuilder, SummaryIndex

__all__ = [
    "Analyzer",
    "Assignment",
    "BasicBlock",
    "BufferInfo",
    "Call",
    "Expr",
    "Finding",
    "FunctionIR",
    "Condition",
    "FunctionSummary",
    "Return",
    "Severity",
    "StackSlot",
    "SummaryBuilder",
    "SummaryIndex",
]

__version__ = "0.6.36"
