#!/usr/bin/env python3
"""Recreate the experiment inputs of the thesis (Section 4) from reproduce/corpus.json.

    python3 reproduce/fetch_corpus.py [--dest DIR] [--sources] [--only ID[,ID...]]

Files of projects with source=github are downloaded from raw.githubusercontent.com at the
pinned commit; constructed inputs (source=included) are copied from reproduce/inputs. Every
file is checked against the SHA-256 recorded in corpus.json. --sources also checks out the
full source tree of the projects used for reachability (git, depth 1) into corpus/src.
The layout under DEST is the one the stored runs scanned (corpus/a/NodeGoat, ...).
"""
import argparse, hashlib, json, os, shutil, subprocess, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def fetch(url, tries=3):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'ssca-reproduce'}), timeout=60) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 - report the last error
            err = e
    raise RuntimeError(f'{url}: {err}')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dest', default='.', help='working directory to create corpus/ in (default: .)')
    ap.add_argument('--sources', action='store_true', help='also check out full source trees for --reachability')
    ap.add_argument('--only', default='', help='comma-separated project ids')
    a = ap.parse_args()
    doc = json.load(open(os.path.join(HERE, 'corpus.json')))
    only = set(filter(None, a.only.split(',')))
    bad = 0
    for p in doc['projects']:
        if only and p['id'] not in only:
            continue
        base = os.path.join(a.dest, p['path'])
        for rel, want in p['files'].items():
            dst = os.path.join(base, rel)
            if p['source'] == 'github':
                data = fetch(f"https://raw.githubusercontent.com/{p['repo']}/{p['commit']}/{rel}")
            else:
                data = open(os.path.join(HERE, 'inputs', p['path'], rel), 'rb').read()
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            open(dst, 'wb').write(data)
            for extra in p.get('also_at', []):
                x = os.path.join(a.dest, extra, rel)
                os.makedirs(os.path.dirname(x), exist_ok=True)
                open(x, 'wb').write(data)
            if sha256(data) != want:
                bad += 1
                print(f'MISMATCH {p["id"]}: {rel}', file=sys.stderr)
        if a.sources and p.get('source_tree'):
            tree = os.path.join(a.dest, p['source_tree'])
            if not os.path.isdir(os.path.join(tree, '.git')):
                os.makedirs(tree, exist_ok=True)
                run = lambda *c: subprocess.run(['git', '-C', tree, *c], check=True, capture_output=True)
                run('init', '-q'); run('remote', 'add', 'origin', f"https://github.com/{p['repo']}.git")
                run('fetch', '-q', '--depth', '1', 'origin', p['commit']); run('checkout', '-q', 'FETCH_HEAD')
        print(f"ok  {p['id']:28s} {len(p['files'])} files  {p['path']}")
    if bad:
        sys.exit(f'{bad} file(s) differ from corpus.json')


if __name__ == '__main__':
    main()
