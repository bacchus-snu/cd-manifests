#!/usr/bin/env python3

import argparse
from string import Template

import yaml

default_template = '${image}:${tag}'

from patch_yaml import patch_yaml

def patch_application(application, image, tag):
    with open('mapping.yaml', 'r') as f:
        mapping = yaml.safe_load(f)

    for m in mapping:
        if m['application'] != application:
            continue
        template = m.get('template', default_template)
        patch_yaml(m['filename'], m['path'], Template(template).substitute(image=image, tag=tag))

        print(f'patching {m["filename"]}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('application')
    parser.add_argument('image')
    parser.add_argument('tag')

    args = parser.parse_args()
    patch_application(**vars(args))

if __name__ == '__main__':
    main()
