The following is an example of polyswarm scan ouput, and what the current PolySwarm
API provides:

```json
[
    {
        "files": [
            {
                "assertions": [
                    {
                        "author": "0x3750266F07E0590aA16e55c32e08e48878010f8f",
                        "bid": 62500000000000000,
                        "engine": "clamav-engine",
                        "mask": true,
                        "metadata": "Legacy.Trojan.Agent-1388596",
                        "verdict": true
                    },
                    {
                        "author": "0x59Af39803354Bd08971Ac8e7C6dB7410a25Ab8DA",
                        "bid": 62500000000000000,
                        "engine": "xvirus",
                        "mask": true,
                        "metadata": "",
                        "verdict": false
                    },
                    {
                        "author": "0xA4815D9b8f710e610E8957F4aD13F725a4331cbB",
                        "bid": 62500000000000000,
                        "engine": "ikarus",
                        "mask": true,
                        "metadata": "Virus.VBS.Ramnit",
                        "verdict": true
                    }
                ],
                "bounty_guid": "778f0423-ebf4-4890-88ac-912d29d91967",
                "bounty_status": "Settled",
                "failed": false,
                "filename": "01495ffe6db270f15928e5a118709a659934463a705227dbc8b688d54f73b702",
                "hash": "01495ffe6db270f15928e5a118709a659934463a705227dbc8b688d54f73b702",
                "result": null,
                "size": 143220,
                "votes": [
                    {
                        "arbiter": "0x1f50Cf288b5d19a55ac4c6514e5bA6a704BD03EC",
                        "engine": "hatchingarb",
                        "vote": false
                    }
                ],
                "window_closed": true
            }
        ],
        "forced": false,
        "permalink": "https://polyswarm.network/scan/results/5a157c83-406e-486b-b3b3-a8984193a2ef",
        "status": "Bounty Settled",
        "uuid": "5a157c83-406e-486b-b3b3-a8984193a2ef"
    }
]
```

Currently, UUID lookups, hash searches, and file scan all return data in this same
format: a list of scan results. A scan result is made up of the following fields:
- files: a list of file results in the scan.
  - assertions: a list of the determinations made by each engine that responded
    - author: the ETH address of the engine
    - bid: the amount the engine attached to their assertion
    - engine: the name of the engine, if known
    - mask: whether the engine is asserting on this file
    - metadata: information regarding why the engine asserted this way
    - verdict: true if malicious, false if not. Should be ignored if mask is false.
  - bounty_guid: a GUID that can be used to lookup the bounty on the sidechain
  <!--- TODO there are other statuses here that need documenting --->
  - bounty_status: The status of the bounty. "settled" means it has finished.
  - failed: whether the bounty failed for some reason
  - filename: the reported filename of the upload
  - hash: the sha256 hash of the file
  - size: size of the file 
  - votes: a list of the votes of the arbiters
    - arbiter: ETH address of the arbiter
    - engine: name of the arbiter, if available
    - vote: determiniation as to maliciousness
  - window_closed: if all the assertions have been made and revealed and results are complete
- forced: whether the files were forcibly re-scanned
- permalink: a permanent link to the scan results
<!--- TODO more statuses need editing here too --->
- status: Whether the entire bounty was settled
- uuid: UUID that can be used to look up this bounty in the PolySwarm API
  
- 
- 
