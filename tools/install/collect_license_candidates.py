#!/usr/bin/env python3
"""Collect candidate notices for review, not a final release SBOM or legal finding.

Inputs must be from the exact build's cargo metadata, target-specific normal and
build dependency tree, and Cargo.lock. Recovered upstream evidence is kept with
its provenance. No network access or artifact distribution is performed.
"""
import argparse, hashlib, json, pathlib, re, shutil, tomllib

p=argparse.ArgumentParser(description=__doc__)
for key in ('metadata','tree','lock','recovered','output'): p.add_argument('--'+key,required=True,type=pathlib.Path)
a=p.parse_args(); meta=json.loads(a.metadata.read_text()); tree=a.tree.read_text(); lock=tomllib.loads(a.lock.read_text())
pairs=set(re.findall(r'^([A-Za-z0-9_-]+) v([^\s]+)',tree,re.M))
if not pairs: raise ValueError('empty dependency tree')
lookup={(x['name'],x['version']):x.get('checksum') for x in lock['package']}
packages=[p for p in meta['packages'] if (p['name'],p['version']) in pairs]
if {(p['name'],p['version']) for p in packages} != pairs: raise ValueError('metadata and tree disagree')
prov=json.loads((a.recovered/'provenance.json').read_text())
a.output.mkdir(mode=0o700,parents=False,exist_ok=False); inventory=[]
for pkg in sorted(packages,key=lambda x:(x['name'],x['version'])):
    name,version=pkg['name'],pkg['version']; source=pkg.get('source')
    record={'name':name,'version':version,'source':source,'license_expression':pkg.get('license'),'files':[]}
    if source and source.startswith('registry+'):
        record['registry_checksum']=lookup.get((name,version))
        if not record['registry_checksum']: raise ValueError('missing Cargo.lock checksum')
        base=pathlib.Path(pkg['manifest_path']).parent; dest=a.output/(name+'-'+version)
        for path in sorted(base.rglob('*')):
            if not path.is_file() or path.is_symlink() or not re.match(r'(?i)^(license|licence|copying|notice|unlicense)([._-].*)?$',path.name): continue
            rel=path.relative_to(base); data=path.read_bytes()
            if len(data)>2_000_000: raise ValueError('unusually large notice')
            target=dest/rel; target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            record['files'].append({'path':str(rel),'sha256':hashlib.sha256(data).hexdigest(),'origin':'registry package'})
        for item in prov['evidence']:
            if not item['file'].startswith(name+'-'+version+'-'): continue
            data=(a.recovered/item['file']).read_bytes()
            if hashlib.sha256(data).hexdigest()!=item['file_sha256']: raise ValueError('recovered evidence mismatch')
            rel=pathlib.Path('recovered-upstream')/item['file'];target=dest/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            record['files'].append({'path':str(rel),'sha256':item['file_sha256'],'origin':item['source'],'scope':item['scope']})
    inventory.append(record)
(a.output/'inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
shutil.copyfile(a.lock,a.output/'Cargo.lock');shutil.copyfile(a.tree,a.output/'cargo-tree.txt')
(a.output/'SCOPE.txt').write_text('CANDIDATE EVIDENCE ONLY. This is not a final artifact SBOM. Review all local crates, license alternatives, nested/native notices, source availability, dependency selection, and upstream VP-Core before distribution.\n')
missing=[p['name']+'@'+p['version'] for p in inventory if p.get('source','') and p['source'].startswith('registry+') and not p['files']]
print(json.dumps({'identities':len(inventory),'registry_missing_candidates':missing,'local_identities_requiring_review':sum(not p.get('source') for p in inventory)}))
if missing: raise SystemExit(1)
