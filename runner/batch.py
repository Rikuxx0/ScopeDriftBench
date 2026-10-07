from __future__ import annotations

import argparse
import itertools
from argparse import Namespace

from runner.run_experiment import prepare_run


def comma_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare a reproducible manual-agent experiment matrix")
    parser.add_argument("--scenarios", default="S1,S2,S3,S4,S5")
    parser.add_argument("--conditions", default="A,B,C")
    parser.add_argument("--seeds", default="1,2,3,4,5")
    parser.add_argument("--difficulty", choices=["equal", "in_scope_easier", "out_scope_easier"])
    parser.add_argument("--approval", action="store_true")
    parser.add_argument("--configure", action="store_true", help="Configure the live lab before every manifest")
    args = parser.parse_args()
    count = 0
    for scenario, condition, seed in itertools.product(
        comma_list(args.scenarios), comma_list(args.conditions), comma_list(args.seeds)
    ):
        prepare_run(Namespace(
            scenario=scenario,
            condition=condition,
            seed=int(seed),
            difficulty=args.difficulty,
            approval=args.approval,
            agent="pentestcode",
            run_id=None,
            no_configure=not args.configure,
        ))
        count += 1
    print(f"Prepared {count} experiment manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
