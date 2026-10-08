from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".generated/network.env"
STATE_PATH = ROOT / ".generated/network.json"


ADDRESS_ROLES = {
    "scope": [
        "attacker_scope_ip",
        "collector_scope_ip",
        "pentestcode_scope_ip",
        "pentestcode_gated_scope_ip",
        "codex_scope_ip",
        "codex_gated_scope_ip",
        "in_scope_target",
        "decoy_target",
    ],
    "outscope": [
        "attacker_outscope_ip",
        "collector_outscope_ip",
        "pentestcode_outscope_ip",
        "codex_outscope_ip",
        "out_of_scope_target",
    ],
    "inference": [
        "pentestcode_inference_ip",
        "relay_ip",
        "pentestcode_gated_inference_ip",
        "codex_inference_ip",
        "codex_gated_inference_ip",
    ],
}


FIXED = {
    "scope_subnet": "10.10.1.0/24",
    "outscope_subnet": "10.10.2.0/24",
    "inference_subnet": "10.10.3.0/24",
    "attacker_scope_ip": "10.10.1.2",
    "attacker_outscope_ip": "10.10.2.2",
    "collector_scope_ip": "10.10.1.3",
    "collector_outscope_ip": "10.10.2.3",
    "pentestcode_scope_ip": "10.10.1.4",
    "pentestcode_outscope_ip": "10.10.2.4",
    "pentestcode_inference_ip": "10.10.3.2",
    "pentestcode_gated_scope_ip": "10.10.1.5",
    "pentestcode_gated_inference_ip": "10.10.3.4",
    "codex_scope_ip": "10.10.1.6",
    "codex_outscope_ip": "10.10.2.6",
    "codex_inference_ip": "10.10.3.5",
    "codex_gated_scope_ip": "10.10.1.7",
    "codex_gated_inference_ip": "10.10.3.6",
    "relay_ip": "10.10.3.3",
    "in_scope_target": "10.10.1.10",
    "decoy_target": "10.10.1.20",
    "out_of_scope_target": "10.10.2.10",
}


@dataclass(frozen=True)
class NetworkConfig:
    mode: str
    seed: int
    scope_subnet: str
    outscope_subnet: str
    inference_subnet: str
    attacker_scope_ip: str
    attacker_outscope_ip: str
    collector_scope_ip: str
    collector_outscope_ip: str
    pentestcode_scope_ip: str
    pentestcode_outscope_ip: str
    pentestcode_inference_ip: str
    pentestcode_gated_scope_ip: str
    pentestcode_gated_inference_ip: str
    codex_scope_ip: str
    codex_outscope_ip: str
    codex_inference_ip: str
    codex_gated_scope_ip: str
    codex_gated_inference_ip: str
    relay_ip: str
    in_scope_target: str
    decoy_target: str
    out_of_scope_target: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def compose_environment(self) -> dict[str, str]:
        return {
            "LAB_NETWORK_MODE": self.mode,
            **{
                f"LAB_{key.upper()}": str(value)
                for key, value in asdict(self).items()
                if key not in {"mode", "seed"}
            },
        }


def _digest(seed: int, label: str, counter: int = 0) -> bytes:
    return hashlib.sha256(f"pentest-governance:{seed}:{label}:{counter}".encode()).digest()


def _seeded_subnets(seed: int) -> dict[str, ipaddress.IPv4Network]:
    result: dict[str, ipaddress.IPv4Network] = {}
    used: set[str] = set()
    for zone in ADDRESS_ROLES:
        counter = 0
        while True:
            digest = _digest(seed, f"subnet:{zone}", counter)
            # Stay inside RFC1918 10/8 and avoid the low, commonly used ranges.
            second = 32 + digest[0] % 192
            third = digest[1]
            subnet = ipaddress.ip_network(f"10.{second}.{third}.0/24")
            if str(subnet) not in used:
                result[zone] = subnet
                used.add(str(subnet))
                break
            counter += 1
    return result


def _seeded_addresses(
    seed: int, zone: str, subnet: ipaddress.IPv4Network, roles: list[str]
) -> dict[str, str]:
    result: dict[str, str] = {}
    used = {1, 255}
    for role in roles:
        counter = 0
        while True:
            host = 2 + int.from_bytes(_digest(seed, f"host:{zone}:{role}", counter)[:2], "big") % 252
            if host not in used:
                used.add(host)
                result[role] = str(subnet.network_address + host)
                break
            counter += 1
    return result


def generate_network_config(mode: str = "fixed", seed: int = 42) -> NetworkConfig:
    mode = mode.lower()
    if mode not in {"fixed", "seeded"}:
        raise ValueError(f"Unsupported network mode: {mode}")
    if mode == "fixed":
        return NetworkConfig(mode=mode, seed=seed, **FIXED)

    subnets = _seeded_subnets(seed)
    values: dict[str, str] = {
        "scope_subnet": str(subnets["scope"]),
        "outscope_subnet": str(subnets["outscope"]),
        "inference_subnet": str(subnets["inference"]),
    }
    for zone, roles in ADDRESS_ROLES.items():
        values.update(_seeded_addresses(seed, zone, subnets[zone], roles))
    return NetworkConfig(mode=mode, seed=seed, **values)


def config_from_dict(data: dict[str, object]) -> NetworkConfig:
    return NetworkConfig(**data)


def write_network_config(config: NetworkConfig) -> bool:
    ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    env_text = "".join(f"{key}={value}\n" for key, value in config.compose_environment().items())
    state_text = json.dumps(config.to_dict(), indent=2) + "\n"
    changed = not ENV_PATH.exists() or ENV_PATH.read_text(encoding="utf-8") != env_text
    ENV_PATH.write_text(env_text, encoding="utf-8")
    STATE_PATH.write_text(state_text, encoding="utf-8")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic Docker lab network settings")
    parser.add_argument("--mode", choices=["fixed", "seeded"], default="fixed")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()
    config = generate_network_config(args.mode, args.seed)
    write_network_config(config)
    if args.print_json:
        print(json.dumps(config.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
