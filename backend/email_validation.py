"""Bounded record validation; not SPF evaluation or DKIM message verification."""
import base64
import binascii
import ipaddress
import re
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import rsa


def spf_syntax(record):
    errors, limitations = [], []
    terms = record.split(' ')
    if terms[0].lower() != 'v=spf1' or any(ord(c) < 32 or ord(c) > 126 for c in record):
        return ['Invalid SPF version or non-SP whitespace/characters.'], []
    seen = set()

    def domain(value):
        if not value:
            errors.append('Missing domain argument.')
        elif '%' in value:
            limitations.append('SPF macro domain syntax/expansion was not validated.')
        elif len(value.rstrip('.')) > 253 or not all(re.fullmatch(r'[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?', label) for label in value.rstrip('.').split('.')):
            errors.append('Invalid SPF domain argument: '+value)

    for term in filter(None, terms[1:]):
        modifier = re.fullmatch(r'([A-Za-z][A-Za-z0-9_.-]*)=(.*)', term)
        if modifier:
            name,value = modifier.groups(); name=name.lower()
            if name in ('redirect','exp'):
                if name in seen:errors.append('Duplicate '+name+' modifier.')
                seen.add(name);domain(value)
            # RFC 7208: unknown modifiers are ignored, not unknown mechanisms.
            continue
        directive = term[1:] if term[0] in '+-~?' else term
        match = re.match(r'^([A-Za-z0-9]+)(.*)$', directive)
        if not match:
            errors.append('Malformed SPF mechanism: '+term);continue
        name,arg = match.groups();name=name.lower()
        if name not in ('all','include','a','mx','ptr','ip4','ip6','exists'):
            errors.append('Unknown SPF mechanism: '+name);continue
        if name=='all':
            if arg:errors.append('all does not accept an argument.')
        elif name in ('ip4','ip6'):
            try:
                if not arg.startswith(':'):raise ValueError()
                net=ipaddress.ip_network(arg[1:],strict=False)
                if net.version != (4 if name=='ip4' else 6):raise ValueError()
                if '/' in arg and not re.fullmatch(r'[0-9]{1,3}',arg.rsplit('/',1)[1]):raise ValueError()
            except ValueError:errors.append('Invalid address/prefix for '+name+': '+arg)
        elif name in ('include','exists'):
            if not arg.startswith(':'):errors.append(name+' requires a domain argument.')
            else:domain(arg[1:])
        elif name=='ptr':
            if arg.startswith(':'):domain(arg[1:])
            elif arg:errors.append('Invalid ptr argument.')
        else:
            if '%' in arg:
                limitations.append('SPF macro domain syntax/expansion was not validated.');continue
            m=re.fullmatch(r'(?::([^/]+))?(?:/([0-9]{1,3}))?(?://([0-9]{1,3}))?',arg)
            if not m:errors.append('Invalid '+name+' domain/CIDR syntax.');continue
            host,v4,v6=m.groups()
            if host:domain(host)
            if v4 and int(v4)>32:errors.append('IPv4 prefix exceeds 32.')
            if v6 and int(v6)>128:errors.append('IPv6 prefix exceeds 128.')
    return list(dict.fromkeys(errors)),list(dict.fromkeys(limitations))


def dkim_key(record):
    tags, errors, limitations = {}, [], []
    fields=[part.strip() for part in record.split(';')]
    if fields and not fields[-1]:fields.pop()
    for part in fields:
        m=re.fullmatch(r'([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)',part)
        if not m:errors.append('Malformed DKIM tag.');continue
        name,value=m.groups()
        if name in tags:errors.append('Duplicate DKIM tag: '+name)
        tags[name]=value.strip()
    if 'v' in tags and (tags['v']!='DKIM1' or not re.match(r'^v\s*=',fields[0])):
        errors.append('DKIM version must be DKIM1 and the first tag when supplied.')
    if 'p' not in tags:return tags, errors+['DKIM public key missing.'], limitations
    public=re.sub(r'[ \t\r\n]','',tags['p'])
    if not public:return tags,errors,limitations  # Revocation is handled separately.
    algorithm=tags.get('k','rsa')
    if algorithm not in ('rsa','ed25519'):
        limitations.append('Unsupported DKIM key algorithm; key not validated: '+algorithm)
        return tags,errors,limitations
    try:
        decoded=base64.b64decode(public,validate=True)
    except (ValueError,binascii.Error):
        return tags,errors+['DKIM p= is not valid base64.'],limitations
    if algorithm=='ed25519':
        if len(decoded)!=32:errors.append('Ed25519 public key must contain 32 bytes.')
    else:
        try:
            key=load_der_public_key(decoded)
            if not isinstance(key,rsa.RSAPublicKey):errors.append('DKIM rsa key is not an RSA public key.')
            elif key.key_size<1024:errors.append('RSA DKIM key is below the 1024-bit minimum.')
        except (ValueError,TypeError,UnsupportedAlgorithm):errors.append('DKIM p= is not a supported DER public key.')
    return tags,errors,limitations
