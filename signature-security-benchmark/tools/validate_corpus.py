#!/usr/bin/env python3
import csv,json,re,hashlib
from pathlib import Path
from collections import Counter,defaultdict
ROOT=Path(__file__).resolve().parents[1]
rows=list(csv.DictReader((ROOT/'manifest.csv').open()))
errors=[]
required=['case_id','filename','contract_name','detector_family','primary_detector','secondary_detectors','label_scope','label','vulnerability_class','subproblem','application_context','verification_mechanism','protection_mechanism','control_flow_shape','rationale','expected_stock_aderyn_0_6_8','expected_custom_detector','source_class','research_basis','semantic_fingerprint','original_case_id']
if rows and list(rows[0].keys())!=required: errors.append('manifest schema/order changed')
for field in ['case_id','filename','contract_name','semantic_fingerprint']:
 vals=[r[field] for r in rows]
 if len(vals)!=len(set(vals)): errors.append(f'duplicate {field}')
expected={'SR':('SignatureReplayDetector',204),'SM':('SignatureMalleabilityDetector',204)}
for fam,(det,count) in expected.items():
 rr=[r for r in rows if r['detector_family']==fam]
 if len(rr)!=count: errors.append(f'{fam} expected {count}, found {len(rr)}')
 for r in rr:
  if not r['case_id'].startswith(fam+'_'): errors.append(f'bad id {r["case_id"]}')
  if not Path(r['filename']).name.startswith(fam+'_'): errors.append(f'bad filename {r["filename"]}')
  if not r['contract_name'].startswith(fam+'_'): errors.append(f'bad contract {r["contract_name"]}')
  if r['primary_detector']!=det or r['label_scope']!=det: errors.append(f'bad detector metadata {r["case_id"]}')
manifest_files={r['filename'] for r in rows}
support={'contracts/SR_ReplayBenchLib.sol','contracts/SM_MalleabilityBenchLib.sol'}
actual={str(p.relative_to(ROOT)) for p in (ROOT/'contracts').glob('*.sol') if str(p.relative_to(ROOT)) not in support}
if manifest_files!=actual: errors.append(f'manifest/file mismatch missing={len(actual-manifest_files)} extra={len(manifest_files-actual)}')
# source checks
pat=re.compile(r'\b(?:abstract\s+contract|contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)')
decls=[]
for p in sorted((ROOT/'contracts').glob('*.sol')):
 s=p.read_text()
 if 'pragma solidity 0.8.29;' not in s: errors.append(f'bad pragma {p.name}')
 for imp in re.findall(r'import\s+"([^"]+)"\s*;',s):
  if not (p.parent/imp).resolve().exists(): errors.append(f'unresolved import {imp} in {p.name}')
 for name in pat.findall(s):
  decls.append((name,p.name))
  if not (name.startswith('SR_') or name.startswith('SM_')): errors.append(f'unprefixed declaration {name} in {p.name}')
 # delimiters after stripping comments/strings roughly
 t=re.sub(r'/\*.*?\*/','',s,flags=re.S); t=re.sub(r'//.*','',t); t=re.sub(r'"(?:\\.|[^"\\])*"','""',t)
 for a,b in [('(',')'),('{','}'),('[',']')]:
  n=0
  for ch in t:
   if ch==a:n+=1
   elif ch==b:
    n-=1
    if n<0: break
  if n!=0: errors.append(f'unbalanced {a}{b} in {p.name}')
 # duplicate parameter identifiers per function
 for m in re.finditer(r'\bfunction\s+\w+\s*\(([^)]*)\)',t,re.S):
  names=[]
  for part in m.group(1).split(','):
   q=part.strip()
   if not q: continue
   mm=re.search(r'([A-Za-z_]\w*)\s*$',q)
   if mm: names.append(mm.group(1))
  d=[x for x,c in Counter(names).items() if c>1]
  if d: errors.append(f'duplicate function parameters {d} in {p.name}')
name_counts=Counter(n for n,_ in decls)
if any(c>1 for c in name_counts.values()): errors.append('duplicate top-level declarations: '+str([n for n,c in name_counts.items() if c>1]))
for r in rows:
 p=ROOT/r['filename']
 if not p.exists(): errors.append(f'missing {r["filename"]}'); continue
 if f'contract {r["contract_name"]}' not in p.read_text(): errors.append(f'target contract missing {r["case_id"]}')
j=json.loads((ROOT/'manifest.json').read_text())
if [x['case_id'] for x in j]!=[r['case_id'] for r in rows]: errors.append('JSON/CSV case mismatch/order')
# Ground truth counts
sm=[r for r in rows if r['detector_family']=='SM']; lab=Counter(r['label'] for r in sm)
# Aggressive structural normalization for SM cases: erase user-chosen identifiers, literals, comments, and strings.
def _normalized_structure(src):
    src=re.sub(r'/\*.*?\*/','',src,flags=re.S)
    src=re.sub(r'//.*','',src)
    src=re.sub(r'"(?:\\.|[^"\\])*"','""',src)
    tokens=re.findall(r'0x[0-9a-fA-F]+|\b\d+\b|\b[A-Za-z_]\w*\b|\S',src)
    keywords=set('pragma solidity import contract interface library abstract is using for function external public internal private view pure payable returns return if else while do break continue try catch emit event error struct enum mapping memory calldata storage immutable constant override virtual unchecked new delete true false this super assembly let switch case default leave modifier receive fallback anonymous indexed address bool string bytes bytes4 bytes32 uint uint8 uint256 int require assert revert keccak256 sha256 abi ecrecover block msg tx type'.split())
    keep={'recover','tryRecover','recoverRaw','recoverCanonical','tryRecoverCanonical','recoverFlexibleCanonical','split65','splitFlexible','call','delegatecall','encode','encodePacked','concat'}
    out=[]
    for tok in tokens:
        if re.match(r'^[A-Za-z_]\w*$',tok) and tok not in keywords:
            out.append(tok if tok in keep else 'ID')
        elif re.match(r'^\d+$',tok): out.append('NUM')
        elif tok.startswith('0x'): out.append('HEX')
        else: out.append(tok)
    return ' '.join(out)
sm_norm=defaultdict(list)
for r in sm:
    h=hashlib.sha256(_normalized_structure((ROOT/r['filename']).read_text()).encode()).hexdigest()
    sm_norm[h].append(r['case_id'])
sm_dups=[g for g in sm_norm.values() if len(g)>1]
if sm_dups: errors.append(f'aggressive normalized structural duplicate SM groups: {sm_dups}')

if lab!={'vulnerable':120,'safe':84}: errors.append(f'bad SM label counts {dict(lab)}')
# exact source duplicate hashes excluding comments and contract-specific names are checked as a lighter semantic sanity test
hash_groups=defaultdict(list)
for r in sm:
 s=(ROOT/r['filename']).read_text(); clean=re.sub(r'\s+',' ',re.sub(r'//.*','',s))
 clean=clean.replace(r['contract_name'],'TARGET')
 h=hashlib.sha256(clean.encode()).hexdigest(); hash_groups[h].append(r['case_id'])
exactish=[g for g in hash_groups.values() if len(g)>1]
if exactish: errors.append(f'near-exact duplicate SM sources {exactish}')
if errors:
 print('VALIDATION FAILED'); [print('-',e) for e in errors]; raise SystemExit(1)
print('Unified structural validation passed')
print('labeled target cases:',len(rows))
print('Solidity files:',len(list((ROOT/'contracts').glob('*.sol'))))
print('SR cases:',sum(r['detector_family']=='SR' for r in rows))
print('SM cases:',len(sm),'vulnerable:',lab['vulnerable'],'safe:',lab['safe'])
print('unique case IDs:',len({r['case_id'] for r in rows}))
print('unique filenames:',len({r['filename'] for r in rows}))
print('unique target contract names:',len({r['contract_name'] for r in rows}))
print('unique top-level declarations:',len(name_counts))
print('unique semantic fingerprints:',len({r['semantic_fingerprint'] for r in rows}))
print('SM aggressive normalized structures:',len(sm_norm))
