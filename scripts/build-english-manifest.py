#!/usr/bin/env python3
"""Regenerate recognized factory hashes from a pinned, reviewed Git baseline.

Developer-only: requires PyYAML==6.0.3. Review the resulting manifest diff and
upgrade fixtures before committing. This does not modify an installation.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import yaml

ROOT=pathlib.Path(__file__).resolve().parents[1]
ROLE_NAMES={'默认':'Default','二进制分析':'Binary Analysis','数字取证':'Digital Forensics','云安全审计':'Cloud Security Audit','综合漏洞扫描':'Comprehensive Vulnerability Scan','渗透测试':'Penetration Testing','信息收集':'Information Gathering','容器安全':'Container Security','后渗透测试':'Post-exploitation Testing','Web框架测试':'Web Framework Testing','Web应用扫描':'Web Application Scan','API安全测试':'API Security Testing','CTF':'CTF'}

def git(*args):
    return subprocess.check_output(['git','-C',str(ROOT),*args])

def sha(value):
    return hashlib.sha256(value).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',default=json.loads((ROOT/'maintenance/upstream.json').read_text())['fork_base'])
    args=parser.parse_args()
    baseline=git('rev-parse','--verify',args.baseline+'^{commit}').decode().strip()
    paths=git('ls-tree','-rz','--name-only',baseline,'tools','roles','skills','agents','knowledge_base').decode().split('\0')
    entries=[]
    for old in filter(None,paths):
        before=git('show',baseline+':'+old)
        new=old
        if old.startswith('roles/') and old.endswith('.yaml'):
            role=yaml.safe_load(before)
            new='roles/'+ROLE_NAMES.get(role['name'],role['name'])+'.yaml'
        path=ROOT/new
        if not path.is_file():
            continue
        after=path.read_bytes()
        if before!=after or old!=new:
            entries.append({'old_path':old,'new_path':new,'original_sha256':sha(before),'english_sha256':sha(after)})
    old=yaml.safe_load(git('show',baseline+':config.example.yaml'))
    new=yaml.safe_load((ROOT/'config.example.yaml').read_text())
    scalars=[]
    def walk(value,replacement,path=()):
        if isinstance(value,dict) and isinstance(replacement,dict):
            for key,item in value.items():
                if key in replacement:
                    walk(item,replacement[key],path+(key,))
        elif isinstance(value,list) and isinstance(replacement,list):
            for index,item in enumerate(value):
                if index<len(replacement):
                    walk(item,replacement[index],path+(index,))
        elif isinstance(value,str) and isinstance(replacement,str) and re.search('[\u3400-\u9fff]',value):
            if path[-1] not in ['name','message','audit_agent_prompt','audit_agent_prompt_review_edit']:
                raise RuntimeError('Unreviewed config field: '+repr(path))
            scalars.append({'path':path,'original_sha256':sha(value.strip().encode()),'english_sha256':sha(replacement.strip().encode()),'english_value':replacement.strip()})
    walk(old,new)
    manifest={'baseline':baseline,'policy':'Replace recognized factory defaults only; no database migration; preserve custom values and credentials.','files':entries,'config_scalars':scalars}
    (ROOT/'maintenance/bundled-english.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    print(f'{len(entries)} factory files; {len(scalars)} config scalars; baseline {baseline}')

if __name__=='__main__':
    main()
