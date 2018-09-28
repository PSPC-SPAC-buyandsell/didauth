import base64
import binascii
import email.utils
import re
import struct
from urllib.request import parse_http_list

import base58
import multidict

from .error import SignerException, VerifierException


def ct_bytes_compare(a, b):
    """
    Constant-time string compare.
    http://codahale.com/a-lesson-in-timing-attacks/
    """
    if not isinstance(a, bytes):
        a = a.decode('utf8')
    if not isinstance(b, bytes):
        b = b.decode('utf8')

    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y

    return (result == 0)


def default_signing_headers(headers, required=None, sign_target=True):
    header_set = {'date'}
    if sign_target:
        header_set.add('(request-target)')
    header_set.update(h.lower() for h in (required or headers.keys()))
    if not sign_target and 'host' in header_set and not required:
        header_set.remove('host')
    # don't sign proxy or connection headers as they could change during routing
    skip_headers = (
        'authorization', 'connection', 'cookie', 'forwarded', 'proxy-connection', 'via',
        'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-proto')
    header_set.difference_update(skip_headers)
    return header_set


def signing_header(name, values):
    if isinstance(values, str):
        value = values
    else:
        value = ', '.join(v.strip() for v in values)
    return '{}: {}'.format(name, value)


def generate_message(required_headers, headers, method=None, path=None) -> bytes:
    headers = multidict.CIMultiDict(headers)

    if not required_headers:
        required_headers = ['date']

    signable_list = []
    for h in required_headers:
        h = h.lower()
        if h == '(request-target)':
            if not method or not path:
                raise SignerException('Method and path arguments required when ' +
                                      'using "(request-target)"')
            signable_list.append(signing_header(h, '{} {}'.format(method.lower(), path)))
        else:
            if h not in headers:
                raise SignerException('Missing required header "{}"'.format(h))
            signable_list.append(signing_header(h, headers.getall(h)))

    signable = '\n'.join(signable_list).encode('ascii')
    return signable


def parse_authorization_header(header):
    if isinstance(header, bytes):
        header = header.decode('ascii')  # HTTP headers cannot be Unicode.

    auth = header.split(' ', 1)
    if len(auth) > 2:
        raise VerifierException('Invalid authorization header. (eg. Method ' +
                                'key1=value1,key2="value, \"2\"")')

    # Split up any args into a dictionary.
    values = multidict.CIMultiDict()
    if len(auth) == 2:
        auth_value = auth[1]
        if auth_value:
            # This is tricky string magic.  Let urllib do it.
            fields = parse_http_list(auth_value)

            for item in fields:
                # Only include keypairs.
                if '=' in item:
                    # Split on the first '=' only.
                    key, value = item.split('=', 1)
                    if not key or not value:
                        continue

                    # Unquote values, if quoted.
                    if value[0] == '"':
                        value = value[1:-1]

                    values[key] = value

    # ("Signature", {"headers": "date", "algorithm": "hmac-sha256", ... })
    return (auth[0], values)


def build_signature_template(key_id, algorithm, headers):
    """
    Build the Signature template for use with the Authorization header.

    key_id is the mandatory label indicating to the server which secret to use
    algorithm is one of the supported algorithms
    headers is a list of http headers to be included in the signing string.

    The signature must be interpolated into the template to get the final
    Authorization header value.
    """
    param_map = {'keyId': key_id,
                 'algorithm': algorithm,
                 'signature': '%s'}
    if headers:
        headers = [h.lower() for h in headers]
        param_map['headers'] = ' '.join(headers)
    kv = map('{0[0]}="{0[1]}"'.format, param_map.items())
    kv_string = ','.join(kv)
    sig_string = 'Signature {0}'.format(kv_string)
    return sig_string


def encode_string(key, enc_format: str) -> bytes:
    if enc_format == 'base58':
        return base58.b58encode(key)
    elif enc_format == 'base64':
        return base64.b64encode(key)
    elif enc_format == 'hex':
        return binascii.hexlify(key)
    else:
        raise VerifierException('Key format not supported: {}'.format(enc_format))


def decode_string(key, enc_format: str) -> bytes:
    if enc_format == 'base58':
        return base58.b58decode(key)
    elif enc_format == 'base64':
        return base64.b64decode(key)
    elif enc_format == 'hex':
        return binascii.unhexlify(key)
    else:
        raise VerifierException('Key format not supported: {}'.format(enc_format))


def decode_rsa_key(key):
    if isinstance(key, bytes):
        key = key.decode('ascii')
    pfx = re.match(r'\-{4,5}BEGIN (.*?)-', key)
    content = re.sub(r'\s', '', re.sub(r'\-{4,5}[\w|| ]+\-{4,5}', '', key))

    if pfx:
        pfx_type = pfx.group(1)
        if 'PRIVATE KEY' not in pfx_type:
            raise VerifierException('Not recognized as a private key: {}'.format(pfx_type))
        if pfx_type == 'PRIVATE KEY':
            return ('PKCS8', key.encode('ascii'))
        elif pfx_type == 'RSA PRIVATE KEY':
            return ('PKCS1', key.encode('ascii'))
    else:
        return (None, key.encode('ascii'))

    # decode ed25519 key in openssh format
    content = base64.b64decode(content)
    if content.startswith(b'openssh-key-v1'):
        content = content[15:]
        _ciphername, content = parse_asn_str(content)
        _kdfname, content = parse_asn_str(content)
        _kdfoptions, content = parse_asn_str(content)
        _count, content = parse_asn_int(content)
        content, _rest = parse_asn_str(content)

    asn_type, content = parse_asn_str(content)
    result, _rest = parse_asn_str(content)
    return (asn_type.decode('ascii'), result)


def parse_asn_str(asn: bytes):
    length = struct.unpack('>I', asn[:4])[0]
    _bits = asn[4:length+4]
    return asn[4:length+4], asn[length+4:]

def parse_asn_int(asn: bytes):
    val = struct.unpack('>I', asn[:4])[0]
    return val, asn[4:]


def format_date_header():
    return email.utils.formatdate()
