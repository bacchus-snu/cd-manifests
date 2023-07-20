#!/usr/bin/env python3

# Horrible hack to patch YAML while preserving comments and whitespace.
# Will likely fail with anything other than the most YAML-looking files.
# Has the nice perk of working with yaml-string-in-yaml.
#
# In particular, patching key.key2 in the following YAML will work:
#
#   key: |
#       # yaml string in yaml
#       key2: value

import argparse

def patch_yaml(filename, path, value):
    path = path.split('.')[::-1]
    stack = []
    lines = []

    with open(filename, 'r') as f:
        for line in f:
            stripped = line.lstrip()
            indent = line[:-len(stripped)]

            while stack and len(indent) <= len(stack[-1][1]):
                path.append(stack.pop()[0])
            if path and stripped.startswith(f'{path[-1]}:'):
                if len(path) == 1:
                    line = f'{indent}{path[-1]}: {value}\n'
                stack.append((path.pop(), indent))
            lines.append(line)

    with open(filename, 'w') as f:
        f.write(''.join(lines))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    parser.add_argument('path')
    parser.add_argument('value')

    args = parser.parse_args()
    patch_yaml(**vars(args))

if __name__ == '__main__':
    main()
