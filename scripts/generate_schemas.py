#!/usr/bin/env python3
"""Generate structural JSON schemas from the metadata-only Go DTOs (stdlib only).
Runtime enum, referential and graph validation remains authoritative in Go.
"""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
structs = {}
for package in ('model', 'report'):
    source = (ROOT / 'internal' / package / (package + '.go')).read_text()
    for name, body in re.findall(r'type (\w+) struct \{(.*?)\n\}', source, re.S):
        fields = re.findall(r'\w+\s+([\w.*\[\]]+)\s+`json:"([^"\s]+)"`', body)
        structs[package + '_' + name] = (package, fields)


def go_type(package, name):
    if name.startswith('[]'):
        return {'type': ['array', 'null'], 'items': go_type(package, name[2:])}
    if name.startswith('*'):
        return {'anyOf': [go_type(package, name[1:]), {'type': 'null'}]}
    if name == 'time.Time':
        return {'type': 'string', 'format': 'date-time'}
    if name in ('int', 'int64'):
        return {'type': 'integer'}
    if name == 'bool':
        return {'type': 'boolean'}
    if name == 'string':
        return {'type': 'string'}
    key = name.replace('.', '_') if '.' in name else package + '_' + name
    assert key in structs, f'unknown DTO type: {key}'
    return {'$ref': '#/$defs/' + key}


def definition(package, fields):
    props, required = {}, []
    for kind, tag in fields:
        name = tag.split(',')[0]
        props[name] = go_type(package, kind)
        if 'omitempty' not in tag:
            required.append(name)
    return {'type': 'object', 'additionalProperties': False, 'properties': props, 'required': required}

all_defs = {key: definition(*value) for key, value in structs.items()}
for name, entry in [('case', 'model_Case'), ('report', 'report_Report')]:
    defs = {}
    def visit(key):
        if key in defs:
            return
        defs[key] = all_defs[key]
        for target in re.findall(r'"\$ref": "#/\$defs/(\w+)"', json.dumps(defs[key])):
            visit(target)
    visit(entry)
    schema = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
              'title': 'KeyRadar ' + name + ' v1',
              '$comment': 'Structural schema. Go validation additionally enforces enums, references, limits and workflow invariants.',
              '$ref': '#/$defs/' + entry, '$defs': defs}
    schema['$defs'][entry]['properties']['schema_version'] = {'const': 1}
    output = json.dumps(schema, indent=2) + '\n'
    path = ROOT / 'schema' / (name + '.schema.json')
    if args.check:
        assert path.read_text() == output, 'schema drift: regenerate schemas'
    else:
        path.write_text(output)
print('Schemas match Go DTOs' if args.check else 'Generated case and report structural schemas')
