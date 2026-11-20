#!/usr/bin/env python3
"""Re-run the stored ssca runs of the thesis offline and compare them with reproduce/expected.json.

    python3 reproduce/replay.py --ssca PATH --snapshots DIR [--work DIR] [--only TEXT] [--keep]

--snapshots  directory with the data snapshot archives (ssca-snapshot-*.tar.gz, available on request);
             each archive is checked against its SHA-256 in expected.json and extracted once next to it
--work       working directory with the inputs made by fetch_corpus.py (corpus/..., corpus/src for the
             reachability runs); default: the current directory
--only       run only the runs whose name contains TEXT (e.g. a/, b/l4s, casestudy)
The case-study runs check out the branches of github.com/Vlad-Mirzoian/supply-chain-audit-demo (git).
Prints one line per run and a total; the exit code is 1 if any run differs.
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tarfile, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from check import summary  # noqa: E402

DEMO = 'https://github.com/Vlad-Mirzoian/supply-chain-audit-demo.git'


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def snapshot(spec, d, sums):
    """spec: 'NAME.tar.gz' or 'NAME.tar.gz (directory SUB/)' -> extracted cache directory."""
    m = re.match(r'(\S+\.tar\.gz)(?: \(directory (\S+?)/?\))?$', spec)
    name, sub = m.group(1), m.group(2)
    dst = os.path.join(d, name[:-len('.tar.gz')])
    if not os.path.isdir(dst):
        arc = os.path.join(d, name)
        if sha256(arc) != sums[name]:
            sys.exit(f'{name}: SHA-256 differs from expected.json')
        os.makedirs(dst)
        with tarfile.open(arc) as t:
            t.extractall(dst, filter='data')
    return os.path.join(dst, sub) if sub else dst


def demo_branch(work, branch):
    dst = os.path.join(work, 'supply-chain-audit-demo', branch)
    if not os.path.isdir(dst):
        subprocess.run(['git', 'clone', '-q', '--branch', branch, '--depth', '1', DEMO, dst], check=True)
    return dst


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ssca', required=True)
    ap.add_argument('--snapshots', required=True)
    ap.add_argument('--work', default='.')
    ap.add_argument('--only', default='')
    ap.add_argument('--keep', action='store_true', help='keep the reports (in WORK/replay-out)')
    a = ap.parse_args()
    doc = json.load(open(os.path.join(HERE, 'expected.json')))
    work = os.path.abspath(a.work)
    outroot = os.path.join(work, 'replay-out') if a.keep else tempfile.mkdtemp(prefix='ssca-replay-')
    same = diff = 0
    for r in doc['runs']:
        if a.only and a.only not in r['run']:
            continue
        cache = snapshot(r['snapshot'], os.path.abspath(a.snapshots), doc['snapshots_sha256'])
        if r['cwd'].startswith('supply-chain-audit-demo'):
            cwd = demo_branch(work, r['cwd'].split('branch ')[1].rstrip(')'))
        else:
            cwd = os.path.join(work, r['cwd'])
        args = [os.path.join(HERE, x[len('reproduce/'):]) if x.startswith('reproduce/') else x for x in r['command'][2:]]
        out = os.path.join(outroot, r['run'])
        shutil.rmtree(out, ignore_errors=True)
        p = subprocess.run([os.path.abspath(a.ssca), 'scan', '--quiet', '--out', out] + args, cwd=cwd,
                           env=dict(os.environ, SSCA_CACHE=cache), capture_output=True, text=True)
        try:
            got = summary(json.load(open(os.path.join(out, 'report.json'))))
        except (OSError, ValueError):
            got = {'error': p.stderr.strip()[-200:]}
        want = r['expected']
        bad = [k for k in want if want[k] is not None and want[k] != got.get(k)]  # None: not compared
        if bad:
            diff += 1
            print(f"DIFF  {r['run']}: " + '; '.join(f'{k}: expected {want[k]}, got {got.get(k)}' for k in bad), flush=True)
        else:
            same += 1
            print(f"same  {r['run']}  ({got['verdict']}, {got['components']} components, {got['findings']} findings)", flush=True)
    if not a.keep:
        shutil.rmtree(outroot, ignore_errors=True)
    print(f'TOTAL {same + diff} runs: {same} as in the thesis, {diff} different')
    sys.exit(1 if diff else 0)


if __name__ == '__main__':
    main()
