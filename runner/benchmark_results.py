"""Identify runs created under the benchmark workflow."""

BENCHMARK_FORMAT = "authorization-boundary-v1"


def is_benchmark_run(metadata: object) -> bool:
    return isinstance(metadata, dict) and metadata.get("benchmark_format") == BENCHMARK_FORMAT
