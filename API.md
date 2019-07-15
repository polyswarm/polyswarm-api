## PolySwarm API

New in v0.3: Initial support for the new hunting/search/stream APIs. This version made some breaking changes to the
search endpoint, so please update. More documentation on the new APIs will be added as features roll out.

New in v0.2: Each community has its own endpoint. To support the new API, simply prepend the community you wish to interact with to the URL. For most, this will be `/epoch/`.

### **POST** `/[community]`

Requires authentication.

Upload files to this endpoint. Returns a uuid to identify the submission. Add `?force=true` to forcibly rescan files.

Fields in JSON response:
- status: the status of the request. OK if successful.
- result: A UUID of the most recent scan of the file, if it was found.

### **GET** `/[community]/hash/[sha256]`

Requires authentication.

Returns a community-specific uuid for a submission that contains this file.
If hash exists in the archive but has no available scan results, a rescan will be scheduled and the UUID
of this new scan returned.

Fields in JSON response:
- status: the status of the request. OK if successful.
- result: A UUID of the most recent scan of the file, if it was found.

### **GET** `/[community]/uuid/[uuid]`

Returns the current state of the submission, complete with scan results if completed. The full JSON format is described in the JSON format section under "Bounty Results".

### **GET** `/[community]/rescan/[hash_type]/[hash]`

Requires authentication.

Initiates a scan of an already submitted artifact, identified by a `hash_type` hash , using the specified community.
Supported hash types are sha256/sha1/md5. 

Fields in JSON response:
- status: the status of the request. OK if successful.
- result: A UUID of the newly initiated scan

### **GET** `/download/[hash_type]/[hash]`

Requires authentication.

Download a file by its `hash_type` hash.
Supported hash types are sha256/sha1/md5.
Response is the file data.

### **GET** `/search`

Requires authentication.

This path accepts three GET paramters:
- type: string, type of hash to search for
- hash: hash, the hash to search for
- query: boolean, search by metadata instead. This also requires a JSON POST body.

Response is described in the JSON Format section below, under "Search Results".

## JSON Format
### Bounty Results
The following an example of the results returned from the **GET**`/[community]/uuid/[uuid]` endpoint from which scan results can be retrieved.

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
                "file_info":
                    {
                        "community": "gamma",
                        "consumer_guids": [
                                              ["5a157c83-406e-486b-b3b3-a8984193a2ef", "gamma"]
                        ],
                        "extended_type": "HTML document, ISO-8859 text, with very long lines, with CRLF line terminators",
                        "filenames": ["01495ffe6db270f15928e5a118709a659934463a705227dbc8b688d54f73b702"],
                        "hash": "01495ffe6db270f15928e5a118709a659934463a705227dbc8b688d54f73b702",
                        "md5": "d300be35bac16e363ff30fe5fd5c963c",
                        "mimetype": "text/html",
                        "sha1": "20024dc28fef2f6fc2982352df66a4f9ad65aa11",
                        "size": 143220,
                        "timestamp": 1550439559
                    },
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
  - file_info: an optional dictionary currently only returned by the search API. Not guaranteed to exist.
    - community: community in which this file was first seen
    - consumer_guids: a list of all historical scan GUID/community pairs
    - extend_type: extended file information as reported by `libmagic`
    - filenames: list of all filenames that have been reported for this sample
    - hash: sha256 hash of the file
    - md5: md5 hash of the file
    - mimetype: mimetype of the file as reported by `libmagic`
    - sha1: sha1 hash of the file
    - size: file size of the file
    - timestamp: time the file was first seen
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

### Search Results

An example search response can be seen below:

```json
[
      {
        "artifact_instances": [
          {
            "artifact_id": 16301091586689620,
            "bounty_id": null,
            "bountyresult": {
              "files": [
                {
                  "assertions": [
                    {
                      "author": "0x0D14c9F70301CeB14CaDD847e87AA3b55C72BafD",
                      "bid": "62500000000000000",
                      "mask": true,
                      "metadata": "EICAR-Test-File",
                      "verdict": true
                    }
                  ],
                  "bounty_guid": "d187d4a2-7410-4a70-a5ee-73fd0533a90d",
                  "bounty_status": "Settled",
                  "failed": false,
                  "filename": "eicar",
                  "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                  "result": null,
                  "size": 68,
                  "votes": [
                    {
                      "arbiter": "0x29F9c138F445dde9330361b4DCf3DB635faB2672",
                      "vote": true
                    },
                    {
                      "arbiter": "0x04C9aa5EcfD2EB126e93ef6D890c7d669Acd1028",
                      "vote": true
                    }
                  ],
                  "window_closed": true
                }
              ],
              "forced": true,
              "status": "Bounty Settled",
              "uuid": "407dbdde-3505-4de4-a2df-ce1896e01053"
            },
            "community": "lima",
            "consumer_guid": "16cb33d2-4a8f-472f-9884-293a5b1d1e72",
            "country": "US",
            "id": 8082705883320936,
            "name": "eicar"
          }
        ],
        "artifact_metadata": [
          {
            "tool": "strings",
            "tool_metadata": {
              "domains": [],
              "ipv4": [],
              "ipv6": [],
              "urls": []
            }
          }
        ],
        "extended_type": "EICAR virus test files",
        "id": 16301091586689620,
        "md5": "69630e4574ec6798239b091cda43dca0",
        "mimetype": "text/plain",
        "sha1": "cf8bd9dfddff007f75adf4c2be48005cea317c62",
        "sha256": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"
      }
]
```

The basic format is a list of artifacts, which then under them contain information on every time the network has seen
the files, what votes/assertions where made, and what metadata was gathered from them.

An artifact object has the following properties, which may be null:
- artifact_instances (a list of times the artifact was seen, and information about it)
- artifact_metadata (a list of results from various tools run internally)
- extended_type
- id
- md5
- mimetype
- sha1
- sha256


Digging into the artifact_instances, you have the following information available:
- artifact_id
- bounty_id
- bountyresults (a bounty result object)
- community
- consumer_guid
- country (guessed roughly by geoip, if submitted through PolySwarm's APIs)
- id
- name (the original filename)

Finally, there is a bounty result object. This object is identical to the result object described in the previous
section.
