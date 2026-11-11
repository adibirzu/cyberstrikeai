#!/usr/bin/env python3
"""Plan, or explicitly apply, replacements of recognized bundled defaults only.

This never opens the database. Only recognized factory config scalars may change;
custom values, credentials and persisted content are preserved. --apply requires an explicit backup directory.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe(root, relative):
    rel = pathlib.PurePosixPath(relative)
    if rel.is_absolute() or '..' in rel.parts:
        raise ValueError('invalid manifest path')
    path = root.joinpath(*rel.parts)
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('symlink/outside-root path refused: '+relative)
    return path


def yaml_semantics(node, replacements=None, path=(), ancestors=frozenset()):
    """Compare YAML values without retaining alias sharing or exposing values."""
    if node is None:
        return None
    if id(node) in ancestors:
        raise RuntimeError('Cyclic configuration requires manual migration')
    ancestors = ancestors | {id(node)}
    replacements = replacements or {}
    if node.id == 'scalar':
        return node.tag, replacements.get(path, node.value)
    if node.id == 'sequence':
        return node.tag, tuple(yaml_semantics(value, replacements, path+(index,), ancestors)
                               for index, value in enumerate(node.value))
    entries = []
    keys = set()
    for key, value in node.value:
        if key.id != 'scalar' or (key.tag, key.value) in keys:
            raise RuntimeError('Complex or duplicate configuration keys require manual migration')
        keys.add((key.tag, key.value))
        entries.append(((key.tag, key.value), yaml_semantics(value, replacements, path+(key.value,), ancestors)))
    return node.tag, tuple(entries)


def scalar_token(value, original):
    # JSON strings are valid YAML scalars in mappings and sequence items. Keep
    # the consumed block-scalar separator so the following key stays separate.
    trailing = re.search(r'(?:\r\n|\r|\n)[ \t]*\Z', original)
    return json.dumps(value, ensure_ascii=True)+(trailing.group() if trailing else '')


def preserve_owner_mode(path, original):
    current = path.stat(follow_symlinks=False)
    if hasattr(os, 'chown') and (current.st_uid, current.st_gid) != (original.st_uid, original.st_gid):
        os.chown(path, original.st_uid, original.st_gid, follow_symlinks=False)
    os.chmod(path, stat.S_IMODE(original.st_mode))


def file_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_mtime_ns)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install-root', required=True, type=pathlib.Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--backup-dir', type=pathlib.Path)
    args = parser.parse_args()
    if args.apply and not args.backup_dir:
        parser.error('--apply requires --backup-dir pointing to a new backup directory')
    source = pathlib.Path(__file__).resolve().parents[1]
    manifest = json.loads((source/'maintenance/bundled-english.json').read_text())
    install = args.install_root.resolve()
    if not install.is_dir():
        parser.error('install root must be an existing directory')
    plans = []
    for entry in manifest['files']:
        old = safe(install,entry['old_path'])
        new = safe(install,entry['new_path'])
        shipped = safe(source,entry['new_path'])
        if not shipped.is_file() or digest(shipped) != entry['english_sha256']:
            raise RuntimeError('shipped replacement differs from reviewed manifest: '+entry['new_path'])
        state = 'absent'
        if old.is_file():
            current = digest(old)
            if old == new and current == entry['english_sha256']:
                state = 'already_english'
            elif current == entry['original_sha256']:
                if new != old and new.exists() and (not new.is_file() or digest(new) != entry['english_sha256']):
                    state = 'blocked_existing_destination'
                else:
                    state = 'replace_recognized_default'
            else:
                state = 'blocked_operator_content'
        elif new.is_file():
            state = 'already_english' if digest(new) == entry['english_sha256'] else 'blocked_operator_content'
        plans.append({**entry,'state':state})
    config_path = safe(install, 'config.yaml')
    config_edits = []
    config_states = []
    config_original = None
    config_original_bytes = None
    config_metadata = None
    config_rendered = None
    config_replacements = {}
    if manifest.get('config_scalars') and config_path.is_file():
        try:
            import yaml
        except ImportError:
            raise RuntimeError('Config migration requires the pinned developer dependency PyYAML==6.0.3; install it in an isolated environment before retrying') from None
        config_original_bytes = config_path.read_bytes()
        config_metadata = config_path.stat(follow_symlinks=False)
        try:
            config_original = config_original_bytes.decode('utf-8')
        except UnicodeError:
            raise RuntimeError('Configuration must be UTF-8 for automatic migration') from None
        try:
            document = yaml.compose(config_original)
        except yaml.YAMLError:
            raise RuntimeError('Cannot parse installation config; repair its YAML before migration') from None
        def find(node, keys):
            if not keys:
                return node
            if isinstance(node, yaml.MappingNode):
                for key, value in node.value:
                    if key.value == str(keys[0]):
                        return find(value, keys[1:])
            if isinstance(node, yaml.SequenceNode) and isinstance(keys[0], int) and keys[0] < len(node.value):
                return find(node.value[keys[0]], keys[1:])
            return None
        for entry in manifest['config_scalars']:
            node = find(document, entry['path'])
            state = 'absent'
            if node is not None:
                if not isinstance(node, yaml.ScalarNode) or node.tag != 'tag:yaml.org,2002:str':
                    state = 'blocked_config_type'
                else:
                    current = hashlib.sha256(node.value.strip().encode()).hexdigest()
                    if current == entry['english_sha256']:
                        state = 'already_english'
                    elif current == entry['original_sha256']:
                        state = 'replace_recognized_default'
                        replacement = entry['english_value']
                        if (not isinstance(replacement, str) or
                                hashlib.sha256(replacement.encode()).hexdigest() != entry['english_sha256']):
                            raise RuntimeError('Config replacement differs from reviewed manifest')
                        config_replacements[tuple(entry['path'])] = replacement
                        value = scalar_token(replacement, config_original[node.start_mark.index:node.end_mark.index])
                        config_edits.append((node.start_mark.index, node.end_mark.index, value))
                    elif any('\u3400' <= character <= '\u9fff' for character in node.value):
                        state = 'blocked_operator_config'
                    else:
                        state = 'preserved_custom_english'
            config_states.append({'path': entry['path'], 'state': state})
        if config_edits:
            ordered = sorted(config_edits)
            if any(previous[1] > following[0] for previous, following in zip(ordered, ordered[1:])):
                raise RuntimeError('Overlapping configuration values require manual migration')
            rendered = config_original
            for start, end, value in reversed(ordered):
                rendered = rendered[:start]+value+rendered[end:]
            try:
                rendered_document = yaml.compose(rendered)
            except yaml.YAMLError:
                raise RuntimeError('Generated configuration is invalid; no files changed') from None
            if yaml_semantics(rendered_document) != yaml_semantics(document, config_replacements):
                raise RuntimeError('Configuration migration would change unapproved values; no files changed')
            config_rendered = rendered.encode('utf-8')
    blocked = [p for p in plans if p['state'].startswith('blocked_')]+[p for p in config_states if p['state'].startswith('blocked_')]
    print(json.dumps({'apply_requested':args.apply,'blocked':len(blocked),
                      'files':[{k:p[k] for k in ['old_path','new_path','state']} for p in plans], 'config_scalars':config_states},indent=2))
    if blocked:
        return 1
    if not args.apply:
        return 0
    backup = args.backup_dir.resolve()
    if backup.exists():
        parser.error('backup directory must not already exist')
    backup.mkdir(parents=True, mode=0o700)
    (backup/'plan.json').write_text(json.dumps(plans,indent=2)+'\n')
    if config_edits:
        config_path = safe(install, 'config.yaml')
        if (config_path.read_bytes() != config_original_bytes or
                file_identity(config_path.stat(follow_symlinks=False)) != file_identity(config_metadata)):
            raise RuntimeError('Config changed after planning; stopped without replacing it')
        shutil.copy2(config_path, backup/'config.yaml')
        preserve_owner_mode(backup/'config.yaml', config_metadata)
        with tempfile.NamedTemporaryFile(dir=config_path.parent, delete=False) as temporary:
            temp = pathlib.Path(temporary.name)
            temporary.write(config_rendered)
        try:
            preserve_owner_mode(temp, config_metadata)
            config_path = safe(install, 'config.yaml')
            if (config_path.read_bytes() != config_original_bytes or
                    file_identity(config_path.stat(follow_symlinks=False)) != file_identity(config_metadata)):
                raise RuntimeError('Config changed during staging; stopped without replacing it')
            os.replace(temp, config_path)
        finally:
            temp.unlink(missing_ok=True)
    for entry in plans:
        if entry['state']!='replace_recognized_default':
            continue
        old=safe(install,entry['old_path']);new=safe(install,entry['new_path'])
        if digest(old)!=entry['original_sha256']:
            raise RuntimeError('source changed after planning; stopped before replacing '+entry['old_path'])
        original_metadata = old.stat(follow_symlinks=False)
        saved=safe(backup,entry['old_path']);saved.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(old,saved)
        preserve_owner_mode(saved, original_metadata)
        new.parent.mkdir(parents=True,exist_ok=True)
        # A same-directory atomic rename keeps each file complete. The backup
        # and plan are retained if a later operation fails; no global rollback
        # may discard an operator edit made during migration.
        with tempfile.NamedTemporaryFile(dir=new.parent,delete=False) as temporary:
            temp=pathlib.Path(temporary.name)
            temporary.write(safe(source,entry['new_path']).read_bytes())
        try:
            preserve_owner_mode(temp, original_metadata)
            # Revalidate after staging. Renamed destinations are never replaced:
            # an existing reviewed English copy is reused, while an absent path
            # is created with an exclusive link so a concurrent edit wins.
            old = safe(install, entry['old_path'])
            new = safe(install, entry['new_path'])
            if digest(old) != entry['original_sha256']:
                raise RuntimeError('source changed during staging; retained '+entry['old_path'])
            if old != new:
                if new.exists():
                    if not new.is_file() or digest(new) != entry['english_sha256']:
                        raise RuntimeError('destination changed after planning; retained '+entry['new_path'])
                else:
                    try:
                        os.link(temp, new)
                    except FileExistsError:
                        raise RuntimeError('destination appeared after planning; retained '+entry['new_path']) from None
            else:
                os.replace(temp,new)
        finally:
            temp.unlink(missing_ok=True)
        if old!=new:
            if digest(old)!=entry['original_sha256']:
                raise RuntimeError('legacy file changed during migration; retained '+entry['old_path'])
            old.unlink()
    return 0


if __name__=='__main__':
    raise SystemExit(main())
