# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Release attestation by a three-source artifact quorum."""
from genlayer import *
from urllib.parse import urlparse
import hashlib,json

def enc(v): return json.dumps(v,sort_keys=True,separators=(",",":"))
def ident(v):
    v=v.strip().upper()
    if not 3<=len(v)<=64 or not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in v): raise gl.vm.UserError("invalid release ID")
    return v
def https(v):
    p=urlparse(v.strip())
    if p.scheme!="https" or not p.hostname or p.username or p.password or p.fragment: raise gl.vm.UserError("clean HTTPS URL required")
    return v.strip()
def sources(raw):
    x=json.loads(raw)
    if type(x) is not list or len(x)!=3: raise ValueError("exactly three release sources required")
    out=[]; hosts=set()
    for item in x:
        if type(item) is not dict or set(item)!={"url","version_path","digest_path"}: raise ValueError("invalid release source")
        u=https(item["url"]); host=urlparse(u).hostname.lower()
        if host in hosts: raise ValueError("source hosts must differ")
        for p in (item["version_path"],item["digest_path"]):
            if type(p) is not list or not p or not all(isinstance(k,str) and k for k in p): raise ValueError("invalid JSON path")
        hosts.add(host); out.append({"url":u,"version_path":item["version_path"],"digest_path":item["digest_path"]})
    return out
def at(v,path):
    for k in path: v=v[int(k)] if isinstance(v,list) else v[k]
    return str(v).strip()
def assess(items):
    pairs=[(x["version"],x["digest"]) for x in items]
    counts={p:pairs.count(p) for p in pairs}; winner=max(counts,key=counts.get); support=counts[winner]
    return {"status":"QUORUM_MATCH" if support>=2 else "CONFLICT","version":winner[0] if support>=2 else "","digest":winner[1] if support>=2 else "","support":support,"observations":items}
class BuildBeacon(gl.Contract):
    releases: TreeMap[str,str]
    def __init__(self): pass
    def key(self,o,i): return str(o).lower()+":"+ident(i)
    @gl.public.write
    def register_release(self,release_id:str,project:str,sources_json:str)->None:
        owner=str(gl.message.sender_address).lower(); key=self.key(owner,release_id)
        if self.releases.get(key,""): raise gl.vm.UserError("release ID already exists")
        try: src=sources(sources_json)
        except Exception: raise gl.vm.UserError("invalid release sources")
        self.releases[key]=enc({"id":ident(release_id),"owner":owner,"project":str(project).strip()[:160],"sources":src,"state":"OPEN","status":"","version":"","digest":"","support":0,"observations":[],"digests":[]})
    @gl.public.write
    def attest_release(self,release_id:str)->None:
        key=self.key(str(gl.message.sender_address),release_id); r=json.loads(self.releases.get(key,"{}"))
        if not r or r["state"]!="OPEN": raise gl.vm.UserError("release is not open")
        def run():
            bodies=[gl.nondet.web.get(s["url"]).body.decode("utf-8") for s in r["sources"]]
            items=[{"version":at(json.loads(b),s["version_path"]),"digest":at(json.loads(b),s["digest_path"])} for b,s in zip(bodies,r["sources"])]
            return enc({**assess(items),"digests":[hashlib.sha256(b.encode()).hexdigest() for b in bodies]})
        def valid(x):
            if not isinstance(x,gl.vm.Return): return False
            try:
                bodies=[gl.nondet.web.get(s["url"]).body.decode("utf-8") for s in r["sources"]]; items=[{"version":at(json.loads(b),s["version_path"]),"digest":at(json.loads(b),s["digest_path"])} for b,s in zip(bodies,r["sources"])]
                return json.loads(x.calldata)=={**assess(items),"digests":[hashlib.sha256(b.encode()).hexdigest() for b in bodies]}
            except Exception: return False
        r.update(json.loads(gl.vm.run_nondet_unsafe(run,valid))); r["state"]="ATTESTED"; self.releases[key]=enc(r)
    @gl.public.view
    def get_release(self,owner:str,release_id:str)->str: return self.releases.get(self.key(owner,release_id),"{}")
