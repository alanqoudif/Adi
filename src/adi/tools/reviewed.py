"""Reviewed typed operations. No extra-argument or raw command passthrough."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from adi.knowledge.observations import Observation, ObservationType
from adi.tools.intelligence import safe_target


def bounded_port(parameters, default):
    port = int(parameters.get('port', default))
    if not 1 <= port <= 65535:
        raise ValueError('invalid port')
    return port


def ports_spec(value):
    text = str(value)
    if not re.fullmatch(r'\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*', text):
        raise ValueError('invalid ports')
    for group in text.split(','):
        numbers = list(map(int, group.split('-')))
        if any(not 1 <= n <= 65535 for n in numbers) or numbers[0] > numbers[-1]:
            raise ValueError('invalid port range')
    return text


def build(tool, target, parameters, binary):
    host = safe_target(target)
    if tool == 'rustscan':
        port_value = ports_spec(parameters.get('ports', '22,80,443,445'))
        count = sum((int(p.split('-')[-1]) - int(p.split('-')[0]) + 1) for p in port_value.split(','))
        if count > 256:
            raise ValueError('reviewed RustScan operation limited to 256 ports')
        return [binary, '-a', host, '-g', '-b', '1', '-t', '1000', '-p',
                ports_spec(parameters.get('ports', '22,80,443,445'))]
    if tool == 'openssl':
        port = bounded_port(parameters, urlsplit(target).port or 443 if '://' in target else 443)
        from ipaddress import ip_address
        try:
            ip_address(host)
            verify_flag = '-verify_ip'
        except ValueError:
            verify_flag = '-verify_hostname'
        return [binary, 's_client', '-connect', f'{host}:{port}', '-servername', host,
                '-showcerts', verify_flag, host]
    if tool == 'smbclient':
        return [binary, '-L', host, '-N', '-g', '-p', str(bounded_port(parameters, 445)),
                '--option=client min protocol=SMB2']
    if tool == 'enum4linux-ng':
        # Identity/session metadata only. No RID cycling or directory enumeration.
        return [binary, '-O', '-w', '', '-t', '5', host]
    if tool == 'ldapsearch':
        return [binary, '-x', '-LLL', '-H', f'ldap://{host}:{bounded_port(parameters, 389)}',
                '-s', 'base', '-b', '', '-z', '5', '-l', '5', '(objectClass=*)',
                'namingContexts', 'supportedLDAPVersion', 'supportedSASLMechanisms']
    if tool in {'dig', 'host', 'nslookup'}:
        if tool == 'dig':
            return [binary, '+time=2', '+tries=1', '+noall', '+answer', host, 'A']
        return [binary, host]
    if tool == 'ssh-keyscan':
        return [binary, '-T', '5', '-p', str(bounded_port(parameters, 22)), host]
    if tool in {'tcpdump', 'tshark'}:
        file = parameters.get('capture_file')
        count = int(parameters.get('packet_count', 50))
        if not 1 <= count <= 100:
            raise ValueError('capture packet count outside bound')
        if tool == 'tcpdump':
            base = [binary, '-nn', '-q', '-c', str(count)]
            return base + (['-r', str(file)] if file else ['-i', str(parameters['interface']), 'host', host])
        base = [binary, '-n', '-c', str(count)]
        base += ['-r', str(file)] if file else ['-i', str(parameters['interface']), '-a',
                                              f'duration:{int(parameters["duration"])}', '-f', f'host {host}']
        return base + ['-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport',
                       '-e', 'tcp.dstport', '-e', '_ws.col.Protocol']
    raise ValueError('unsupported reviewed operation')


def parse(tool, stdout, stderr, context):
    target = context['target']
    host = safe_target(target)
    observations = []

    def add(kind, value, subject=target, confidence=1.0):
        observations.append(Observation(type=ObservationType(kind), subject=subject,
                                        value=value, source=tool, confidence=confidence))

    if tool == 'rustscan':
        for line in stdout.splitlines():
            match = re.search(r'([\w.\-]+)\s*->\s*\[([\d, ]+)\]', line)
            if match:
                for port in match[2].split(','):
                    p = int(port.strip())
                    add('open_port', {'host': host, 'port': p, 'protocol': 'tcp',
                                     'service': 'smb' if p == 445 else '', 'state': 'open'},
                        f'{host}:{p}')
    elif tool == 'openssl':
        text = stdout + '\n' + stderr
        metadata = {}
        patterns = {'protocol': r'(?:Protocol\s*:\s*|New, )(TLSv[\d.]+)',
                    'cipher': r'(?:Cipher\s*:\s*|Cipher is )([^\s]+)',
                    'subject': r'subject\s*=\s*([^\n]+)', 'issuer': r'issuer\s*=\s*([^\n]+)',
                    'not_after': r'NotAfter:\s*([^\n]+)',
                    'verification': r'Verify return code:\s*(\d+)'}
        for key, pattern in patterns.items():
            match = re.search(pattern, text)
            if match:
                metadata[key] = match[1].strip()
        metadata['hostname_match'] = (True if metadata.get('verification') == '0' else
                                      False if metadata.get('verification') == '62' else None)
        pem = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.DOTALL)
        if pem:
            from cryptography import x509
            certificate = x509.load_pem_x509_certificate(pem[0].encode())
            metadata.update(subject=certificate.subject.rfc4514_string(),
                            issuer=certificate.issuer.rfc4514_string(),
                            not_after=certificate.not_valid_after_utc.isoformat())
            from ipaddress import ip_address
            try:
                san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                try:
                    metadata['hostname_match'] = ip_address(host) in san.get_values_for_type(x509.IPAddress)
                except ValueError:
                    names = san.get_values_for_type(x509.DNSName)
                    metadata['hostname_match'] = any(
                        host.lower() == name.lower() or (
                            name.startswith('*.') and host.lower().endswith(name[1:].lower())
                            and host.count('.') == name.count('.')) for name in names)
            except x509.ExtensionNotFound:
                metadata['hostname_match'] = None
        if metadata:
            add('tls_observation', metadata)
    elif tool in {'smbclient', 'enum4linux-ng'}:
        if tool == 'smbclient':
            for line in stdout.splitlines():
                parts = line.split('|', 2)
                if len(parts) == 3 and parts[0] in {'Disk', 'IPC', 'Printer'}:
                    add('smb_share', {'name': parts[1], 'kind': parts[0], 'comment': parts[2],
                                      'host': host, 'port': 445}, f'{host}:445/{parts[1]}')
        else:
            if stdout.lstrip().startswith('{'):
                data = json.loads(stdout)
                shares = data.get('shares', {})
                for name, info in shares.items():
                    add('smb_share', {'name': name, 'kind': info.get('type', 'unknown'),
                                     'host': host, 'port': 445}, f'{host}:445/{name}')
                for key in ('smb_domain_info', 'os_info', 'workgroup', 'domain'):
                    if key in data:
                        add('identity_observation', {key: data[key]})
            else:
                for line in stdout.splitlines():
                    if re.search(r'(domain|workgroup|os version|os:)', line, re.IGNORECASE):
                        add('identity_observation', {'metadata': line[:250]}, confidence=0.8)
        if observations and context.get('exit_code', 0) == 0:
            add('open_port', {'host': host, 'port': 445, 'protocol': 'tcp', 'service': 'smb'})
    elif tool == 'ldapsearch':
        entry = {}
        for line in stdout.splitlines():
            if ': ' in line and not line.startswith('#'):
                key, value = line.split(': ', 1)
                if key in {'dn', 'namingContexts', 'supportedLDAPVersion', 'supportedSASLMechanisms'}:
                    entry.setdefault(key, []).append(value)
        if entry:
            add('ldap_observation', entry)
            for value in entry.get('namingContexts', []):
                add('directory_naming_context', {'name': value})
    elif tool in {'tcpdump', 'tshark'}:
        for line in stdout.splitlines()[:100]:
            if tool == 'tshark':
                fields = line.split('\t')
                if len(fields) >= 5:
                    add('network_flow_observation', dict(zip(
                        ('source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol'), fields[:5])))
            else:
                match = re.search(r'IP (\S+) > (\S+): (.*)', line)
                if match:
                    add('network_flow_observation', {'source': match[1], 'destination': match[2],
                                                    'metadata': match[3][:120]})
    elif tool in {'hydra', 'medusa'}:
        text = stdout + stderr
        if stdout.lstrip().startswith('{'):
            data = json.loads(stdout)
            for item in data.get('results', []):
                add('credential_audit_observation', {'success': True, 'account': item.get('login', ''),
                                                      'service': item.get('service', '')})
        else:
            success = bool(re.search(r'login:\s*\S+\s+password:|ACCOUNT FOUND|\[SUCCESS\]', text))
            add('credential_audit_observation', {'success': success})
    elif tool in {'dig', 'host', 'nslookup'}:
        for line in stdout.splitlines():
            match = re.search(r'([\w.\-]+)\s+(\d+)\s+IN\s+(A|AAAA|CNAME|MX|NS|TXT)\s+(.+)', line)
            if match:
                add('dns_record', {'name': match[1], 'ttl': int(match[2]),
                                   'record_type': match[3], 'value': match[4]})
            elif 'has address ' in line or 'Address: ' in line:
                add('resolution_observation', {'metadata': line[:250]})
    elif tool == 'ssh-keyscan':
        for line in stdout.splitlines():
            if line.startswith('#'):
                add('ssh_observation', {'banner': line[:250]})
            else:
                parts = line.split()
                if len(parts) == 3:
                    add('ssh_observation', {'algorithm': parts[1]})
    if stdout.strip() and not observations:
        raise ValueError('unsupported output schema')
    return observations
