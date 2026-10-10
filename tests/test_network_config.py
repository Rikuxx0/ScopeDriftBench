import ipaddress

from runner.network_config import ADDRESS_ROLES, generate_network_config, runtime_topology


def test_fixed_network_preserves_legacy_addresses():
    config = generate_network_config("fixed", 42)
    assert config.scope_subnet == "10.10.1.0/24"
    assert config.in_scope_target == "10.10.1.10"
    assert config.out_of_scope_target == "10.10.2.10"


def test_seeded_network_is_reproducible_and_changes_with_seed():
    first = generate_network_config("seeded", 42)
    repeated = generate_network_config("seeded", 42)
    different = generate_network_config("seeded", 43)
    assert first == repeated
    assert first != different
    assert first.scope_subnet != different.scope_subnet


def test_seeded_addresses_are_unique_and_inside_their_zone():
    config = generate_network_config("seeded", 42)
    values = config.to_dict()
    subnets = {
        "scope": ipaddress.ip_network(config.scope_subnet),
        "outscope": ipaddress.ip_network(config.outscope_subnet),
        "inference": ipaddress.ip_network(config.inference_subnet),
    }
    assert len(set(subnets.values())) == 3
    for zone, roles in ADDRESS_ROLES.items():
        addresses = [ipaddress.ip_address(str(values[role])) for role in roles]
        assert len(addresses) == len(set(addresses))
        assert all(address in subnets[zone] for address in addresses)


def test_runtime_labels_are_opaque_reproducible_and_seed_specific():
    first = runtime_topology(42)
    repeated = runtime_topology(42)
    different = runtime_topology(43)
    assert first == repeated
    assert first != different
    names = [value for key, value in first.items() if key.endswith("_name") and not key.endswith("interface_name")]
    assert len(names) == len(set(names))
    assert not any(
        token in name.lower()
        for name in names
        for token in ("scope", "outscope", "inference", "provider", "seg01", "seg02")
    )


def test_scope_interface_position_is_balanced_across_seeds():
    assignments = [runtime_topology(seed)["scope_interface_name"] for seed in range(64)]
    assert set(assignments) == {"eth1", "eth2"}
    assert assignments.count("eth1") == assignments.count("eth2") == 32
    for seed in range(64):
        topology = runtime_topology(seed)
        assert {topology["scope_interface_name"], topology["outscope_interface_name"]} == {
            "eth1", "eth2"
        }


def test_compose_environment_contains_runtime_topology():
    config = generate_network_config("seeded", 42)
    environment = config.compose_environment()
    assert environment["LAB_SCOPE_NETWORK_NAME"].startswith("pgl-net-")
    assert environment["LAB_IN_SCOPE_CONTAINER_NAME"].startswith("pgl-node-")
    assert environment["LAB_SCOPE_INTERFACE_NAME"] in {"eth1", "eth2"}
