import{readFile,writeFile}from'node:fs/promises';
import{createAccount,createClient}from'genlayer-js';import{studionet}from'genlayer-js/chains';import{TransactionStatus}from'genlayer-js/types';
const key=process.env.GENLAYER_PRIVATE_KEY;if(!key)throw Error('GENLAYER_PRIVATE_KEY is required');
const d=JSON.parse(await readFile(new URL('../artifacts/deployment.json',import.meta.url),'utf8'));const c=createClient({chain:studionet,account:createAccount(key.startsWith('0x')?key:'0x'+key)});
const id='LIVE-'+Date.now();const sources=[{url:'https://api.github.com/repos/github/gitignore',version_path:['name'],digest_path:['id']},{url:'https://registry.npmjs.org/react/latest',version_path:['version'],digest_path:['dist','integrity']},{url:'https://jsonplaceholder.typicode.com/todos/1',version_path:['id'],digest_path:['title']}];
const h=await c.writeContract({address:d.address,functionName:'register_release',args:[id,'BuildBeacon live verification',JSON.stringify(sources)],value:0n});await c.waitForTransactionReceipt({hash:h,status:TransactionStatus.FINALIZED,retries:180,interval:2500});
const a=await c.writeContract({address:d.address,functionName:'attest_release',args:[id],value:0n});await c.waitForTransactionReceipt({hash:a,status:TransactionStatus.FINALIZED,retries:180,interval:2500});
const record=JSON.parse(String(await c.readContract({address:d.address,functionName:'get_release',args:[c.account.address,id]})));if(record.id!==id||!['QUORUM_MATCH','CONFLICT'].includes(record.status))throw Error('readback failed');
await writeFile(new URL('../artifacts/live-verification.json',import.meta.url),JSON.stringify({address:d.address,owner:c.account.address,register_transaction:h,attest_transaction:a,record},null,2)+'\n');console.log('LIVE BUILDBEACON PASSED: '+record.status);
