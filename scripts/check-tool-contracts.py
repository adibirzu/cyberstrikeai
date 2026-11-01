#!/usr/bin/env python3
"""Check reviewed bundled CLI/schema contracts without executing security tools.

Developer-only PyYAML==6.0.3 is required. --write-reviewed records a new contract
only after reviewing its upstream/source diff; CI never uses that option.
"""
import argparse
import ast
import shlex
import hashlib
import json
import pathlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]

def machine(value):
    if isinstance(value, dict):
        return {key: machine(item) for key, item in value.items() if key not in {'description', 'short_description'}}
    if isinstance(value, list):
        return list(map(machine, value))
    return value

def contracts(root):
    result = {}
    names = set()
    for path in sorted((root / 'tools').glob('*.yaml')):
        value = yaml.safe_load(path.read_text())
        if not isinstance(value, dict) or not isinstance(value.get('name'), str) or not isinstance(value.get('command'), str):
            raise ValueError('invalid tool definition: ' + path.name)
        if value['name'] in names:
            raise ValueError('duplicate tool ID: ' + value['name'])
        names.add(value['name'])
        args = value.get('args', [])
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError('invalid argv: ' + path.name)
        if value['command'] in {'python3', 'python'} and '-c' in args:
            index = args.index('-c') + 1
            if index >= len(args):
                raise ValueError('missing Python recipe: ' + path.name)
            compile(args[index], str(path), 'exec')
            # Source comments are not emitted. Literal values (including
            # decoded escapes and f-string segments) are operational text/data.
            tree = ast.parse(args[index], filename=str(path))
            texts = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        else:
            texts = []
            for argument in args:
                lexer = shlex.shlex(argument, posix=True)
                lexer.whitespace_split = True
                texts.extend(lexer)
        texts.extend([value['name'], value['command']])
        if any(any('\u3400' <= character <= '\u9fff' for character in text) for text in texts):
            raise ValueError('untranslated bundled executable literal: ' + path.name)
        encoded = json.dumps(machine(value), sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
        result[path.name] = {'tool_id': value['name'], 'machine_sha256': hashlib.sha256(encoded).hexdigest()}
    if not result:
        raise ValueError('no tools found')
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, default=ROOT)
    parser.add_argument('--write-reviewed', action='store_true')
    args = parser.parse_args()
    current = contracts(args.root)
    # Optional standalone MCP metadata/errors are also product-facing. Parse
    # literals without importing the server or starting any listener/model.
    for script in (args.root / 'mcp-servers').rglob('*.py'):
        tree = ast.parse(script.read_text(), filename=str(script))
        compile(tree, str(script), 'exec')
        if any(isinstance(node, ast.Constant) and isinstance(node.value, str) and any('\u3400' <= char <= '\u9fff' for char in node.value) for node in ast.walk(tree)):
            raise ValueError('untranslated standalone MCP literal: ' + str(script.relative_to(args.root)))
    path = args.root / 'maintenance/tool-contracts.json'
    if args.write_reviewed:
        path.write_text(json.dumps({'policy': 'Reviewed executable argv, tool IDs, enablement and schema/default contracts. Descriptions excluded.', 'tools': current}, indent=2) + '\n')
    else:
        reviewed = json.loads(path.read_text())['tools']
        changed = sorted(name for name in set(current) | set(reviewed) if current.get(name) != reviewed.get(name))
        if changed:
            print(json.dumps({'changed_tool_contracts': changed}))
            return 1
    print(f'Reviewed executable/schema contracts validated: {len(current)} tools; embedded Python compiled and executable literals checked for English without execution')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
