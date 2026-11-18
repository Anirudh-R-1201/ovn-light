#!/usr/bin/env python3
"""Correct the pinned test CRD's uint32 bounds / int32 format mismatch."""
import json
import subprocess
import sys

command = ['kubectl'] + sys.argv[1:]
name = 'networkqoses.k8s.ovn.org'
crd = json.loads(subprocess.check_output(command + ['get', 'crd', name, '-o', 'json']))
patch = []
for index, version in enumerate(crd['spec']['versions']):
    fields = version['schema']['openAPIV3Schema']['properties']['spec']['properties']['egress']['items']['properties']['bandwidth']['properties']
    for field in ('rate', 'burst'):
        schema = fields[field]
        if schema.get('format') != 'int32' or schema.get('maximum') != 4294967295:
            continue
        path = f'/spec/versions/{index}/schema/openAPIV3Schema/properties/spec/properties/egress/items/properties/bandwidth/properties/{field}/format'
        patch += [{'op': 'test', 'path': path, 'value': 'int32'},
                  {'op': 'replace', 'path': path, 'value': 'int64'}]
if patch:
    patch.insert(0, {'op': 'test', 'path': '/metadata/resourceVersion', 'value': crd['metadata']['resourceVersion']})
    subprocess.run(command + ['patch', 'crd', name, '--type=json', '-p', json.dumps(patch)], check=True)
    print('Test CRD workaround: bandwidth keeps uint32 bounds with an int64 OpenAPI format')
