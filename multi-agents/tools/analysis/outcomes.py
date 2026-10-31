"""Analysis outcomes that must not be treated as negative findings."""


class InconclusiveAnalysis(ValueError):
    """Evidence is missing or cannot be represented by the current analyzer."""
