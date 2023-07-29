#!/usr/bin/env python3

import argparse
from string import Template
import subprocess

import yaml

default_template = '${image}:${tag}'

# NOTE: We assume that the input is trusted. Bad things will occur if
# mapping.yaml is malicious, including command injection.

def patch_application(application, image, tag):
    with open('mapping.yaml', 'r') as f:
        mapping = yaml.safe_load(f)

    for m in mapping:
        if m['application'] != application:
            continue
        template = m.get('template', default_template)
        value = Template(template).substitute(image=image, tag=tag)

        q_lhs = ''
        q_rhs = yaml.safe_dump(value, default_style='"').rstrip()
        for p in reversed(m['path']):
            if p == '_YAML':
                q_rhs = f'(from_yaml | ({q_lhs} |= {q_rhs}) | to_yaml)'
                q_lhs = ''
            elif p.startswith('_DOC_'):
                di = int(p[len('_DOC_'):])
                q_lhs = f'(select(di == {di}) | {q_lhs})'
            else:
                q_lhs = f'.{p}{q_lhs}'

        print(f'patching {m["filename"]}')
        subprocess.run(['yq', '-i', f'{q_lhs} |= {q_rhs}', m['filename']], check=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('application')
    parser.add_argument('image')
    parser.add_argument('tag')

    args = parser.parse_args()
    patch_application(**vars(args))

if __name__ == '__main__':
    main()
