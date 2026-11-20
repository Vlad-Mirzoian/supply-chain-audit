#!/usr/bin/env python3
"""Compare the report.json of a re-run with the expected result in reproduce/expected.json.

    python3 reproduce/check.py RUN REPORT_JSON     e.g.  check.py a_default/NodeGoat out/report.json
    python3 reproduce/check.py --list              lists the runs

Compared: verdict and exit code, number of components and findings, vulnerability findings
per severity, violated rules, number of reasons of incompleteness and the data snapshot ID.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def summary(rep):
    dec = rep['decision']
    sev = {}
    for f in rep['findings']:
        if f.get('kind') == 'vulnerability' and not f.get('suppressed'):
            sev[f.get('severity', '?')] = sev.get(f.get('severity', '?'), 0) + 1
    return {'verdict': dec['verdict'], 'exit_code': dec['exit_code'], 'components': len(rep['components']),
            'findings': len(rep['findings']), 'vulnerabilities_by_severity': dict(sorted(sev.items())),
            'violations': sorted({v['rule'] for v in dec['violations'] or []}),
            'incomplete': len(rep.get('incomplete') or []), 'data_snapshot': rep.get('data_snapshot')}


def main():
    runs = {r['run']: r for r in json.load(open(os.path.join(HERE, 'expected.json')))['runs']}
    if len(sys.argv) == 2 and sys.argv[1] == '--list':
        for name, r in runs.items():
            print(f"{name:45s} {r['used_in']:22s} {' '.join(r['command'])}")
        return
    if len(sys.argv) != 3 or sys.argv[1] not in runs:
        sys.exit(__doc__)
    want = runs[sys.argv[1]]['expected']
    got = summary(json.load(open(sys.argv[2])))
    diff = {k: (want[k], got.get(k)) for k in want if want[k] is not None and want[k] != got.get(k)}
    if not diff:
        print(f'{sys.argv[1]}: same as in the thesis ({got["verdict"]}, {got["components"]} components, {got["findings"]} findings)')
        return
    for k, (w, g) in diff.items():
        print(f'{sys.argv[1]}: {k}: expected {w}, got {g}')
    sys.exit(1)


if __name__ == '__main__':
    main()
