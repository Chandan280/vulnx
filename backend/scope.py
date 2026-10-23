"""Validate bounded targets and pin network destinations before scanning."""
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit
from backend.checks import domain_name

LAB_PORTS = {18080, 18443}
PROFILES = {'email', 'network', 'tls', 'web', 'web_active'}


def ports(value):
    try:
        result = sorted({int(p.strip()) for p in value.split(',')})
    except (ValueError, AttributeError):
        raise ValueError('Use comma-separated port numbers, without ranges.')
    if not result or len(result) > 32 or any(p < 1 or p > 65535 for p in result):
        raise ValueError('Choose 1–32 ports between 1 and 65535.')
    return result


def network_target(value):
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise ValueError('Enter an IPv4 address or a subnet of at most 16 addresses.')
    if net.version != 4 or net.num_addresses > 16:
        raise ValueError('Network scans are limited to 16 IPv4 addresses per assessment.')
    for address in net:
        private = any(address in ipaddress.ip_network(cidr) for cidr in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
        if not (address.is_global or private or str(address)=='127.0.0.1') or address.is_multicast:
            raise ValueError('This target includes a reserved, metadata, or unsupported loopback address.')
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def url_target(value, tls=False):
    if tls and '://' not in value:
        value = 'https://' + value
    parsed = urlsplit(value.strip())
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Enter an http(s) URL without credentials.')
    if any(ord(c) < 33 for c in value) or parsed.fragment or parsed.query:
        raise ValueError('Use a target URL without spaces, query strings, or fragments.')
    host = parsed.hostname.lower()
    if host != '127.0.0.1':
        try:
            ip = ipaddress.ip_address(host)
            if not ip.is_global or ip.is_multicast:
                raise ValueError('Only public addresses or the built-in local lab are supported.')
        except ValueError:
            host = domain_name(host)
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    if host == '127.0.0.1' and port not in LAB_PORTS:
        raise ValueError('Local scans are limited to lab ports 18080 and 18443.')
    if tls and parsed.scheme != 'https':
        raise ValueError('TLS assessments require an https target.')
    return urlunsplit((parsed.scheme, f'{host}:{port}', parsed.path or '/', '', ''))


def target(value, kind):
    if kind == 'domain':
        return domain_name(value)
    if kind == 'network':
        return network_target(value)
    if kind == 'website':
        return url_target(value)
    raise ValueError('Unknown asset type.')


def resolved_url(value, tls=False):
    parsed = urlsplit(url_target(value,tls))
    host, port = parsed.hostname, parsed.port
    if host == '127.0.0.1':
        return parsed, '127.0.0.1'
    addresses = list(dict.fromkeys(a[4][0] for a in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(a).is_global or ipaddress.ip_address(a).is_multicast for a in addresses):
        raise ValueError('Target resolution includes a non-public address; assessment blocked.')
    return parsed, addresses[0]


def validate_profile(asset, profile, port_list):
    if profile not in PROFILES:
        raise ValueError('Unknown scan profile.')
    expected = 'domain' if profile=='email' else 'network' if profile=='network' else 'website'
    if asset['kind'] != expected:
        raise ValueError('The selected profile does not match this asset type.')
    if profile == 'network':
        network_target(asset['domain'])
        values = ports(port_list)
        if asset['domain'] == '127.0.0.1' and not set(values).issubset(LAB_PORTS):
            raise ValueError('Local network scans may target only lab ports 18080 and 18443.')
    if profile == 'web_active':
        parsed = urlsplit(asset['domain'])
        if parsed.hostname != '127.0.0.1' or parsed.port != 18080:
            raise ValueError('Active ZAP assessments are currently limited to the local lab at 127.0.0.1:18080.')
