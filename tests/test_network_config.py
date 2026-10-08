import ipaddress

from runner.network_config import ADDRESS_ROLES, generate_network_config


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
