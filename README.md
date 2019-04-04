# polyswarm-api
An interface to the public and private PolySwarm APIs.


## Installation
From PyPI:

`pip install polyswarm-api`

From source:

`python3 setup.py install`

## Usage

To use the library:

```python
import polyswarm_api

# you will need to get your own key from 
# https://polyswarm.network/profile/apiKeys

api_key = "317b21cb093263b701043cb0831a53b9"

api = polyswarm_api.PolyswarmAPI(key=api_key)

results = api.scan_directory("/path/to/directory")

results = api.scan_file("/path/to/eicar")

results = api.search_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

results = api.search_hashes(["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"])

results = api.download_file("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "test/")

results = api.rescan_file("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
```

To use the provided CLI:

```bash
$ export POLYSWARM_API_KEY=<Your API key from polyswarm.network>
$ export POLYSWARM_COMMUNITY=epoch
$ polyswarm
Usage: polyswarm [OPTIONS] COMMAND [ARGS]...

  This is a PolySwarm CLI client, which allows you to interact directly with
  the PolySwarm network to scan files, search hashes, and more.

Options:
  -a, --api-key TEXT              Your API key for polyswarm.network
                                  (required)
  -u, --api-uri TEXT              The API endpoint (ADVANCED)
  -o, --output-file FILENAME      Path to output file.
  --fmt, --output-format [text|json]
                                  Output format. Human-readable text or JSON.
  --color / --no-color            Use colored output in text mode.
  -v, --verbose
  -c, --community TEXT            Community to use.
  -h, --help                      Show this message and exit.

Commands:
  download  download file(s)
  lookup    lookup UUID(s)
  rescan    rescan files(s) by hash
  scan      scan files/directories
  search    search for hash

$ polyswarm scan /tmp/eicar
Scan report for GUID 39b04176-51eb-4431-82d0-a0a3176164f0
=========================================================
Report for file eicar, hash: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
        tachyon: Clean
        nanoav: Malicious, metadata: {"infections": [{"name": "Marker.Dos.EICAR-Test-File.dyb"}]}
        zillya: Malicious
        clamav-engine: Malicious, metadata: Eicar-Test-Signature
        k7-engine: Malicious, metadata: Trojan ( 000139291 )
        ikarus: Malicious, metadata: EICAR-Test-File
        xvirus: Malicious, metadata: 
        drweb: Malicious, metadata: infected with EICAR Test File (NOT a Virus!)
        lionic: Clean

$ polyswarm -o /tmp/test.txt search 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
$ cat /tmp/test.txt
Scan report for GUID 39b04176-51eb-4431-82d0-a0a3176164f0
=========================================================
Report for file eicar, hash: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
        tachyon: Clean
        nanoav: Malicious, metadata: {"infections": [{"name": "Marker.Dos.EICAR-Test-File.dyb"}]}
        zillya: Malicious
        clamav-engine: Malicious, metadata: Eicar-Test-Signature
        k7-engine: Malicious, metadata: Trojan ( 000139291 )
        ikarus: Malicious, metadata: EICAR-Test-File
        xvirus: Malicious, metadata: 
        drweb: Malicious, metadata: infected with EICAR Test File (NOT a Virus!)
        lionic: Clean

$ polyswarm -vvv -o /tmp/test.json --fmt json lookup 39b04176-51eb-4431-82d0-a0a3176164f0
DEBUG:root:Creating API instance: api_key:<redacted>
DEBUG:asyncio:Using selector: EpollSelector

$ cat /tmp/test.json
[{"files": [{"assertions": [{"author": "0x1EdF29c0977aF06215032383F93deB9899D90118", "bid": 62500000000000000, "mask": true, "metadata": "", "verdict": false, "engine": "tachyon"}, {"author": "0x2b4C240B376E5406C5e2559C27789d776AE97EFD", "bid": 62500000000000000, "mask": true, "metadata": "{\"infections\": [{\"name\": \"Marker.Dos.EICAR-Test-File.dyb\"}]}", "verdict": true, "engine": "nanoav"}, {"author": "0xf6019C1f057D26FFB2b41C221E0DB4Ef88931C86", "bid": 62500000000000000, "mask": true, "metadata": null, "verdict": null, "engine": "zillya"}, {"author": "0x3750266F07E0590aA16e55c32e08e48878010f8f", "bid": 62500000000000000, "mask": true, "metadata": "Eicar-Test-Signature", "verdict": true, "engine": "clamav-engine"}, {"author": "0xbE0B3ec289aaf9206659F8214c49D083Dc1a9E17", "bid": 62500000000000000, "mask": true, "metadata": "Trojan ( 000139291 )", "verdict": true, "engine": "k7-engine"}, {"author": "0xA4815D9b8f710e610E8957F4aD13F725a4331cbB", "bid": 62500000000000000, "mask": true, "metadata": "EICAR-Test-File", "verdict": true, "engine": "ikarus"}, {"author": "0x59Af39803354Bd08971Ac8e7C6dB7410a25Ab8DA", "bid": 62500000000000000, "mask": true, "metadata": "", "verdict": true, "engine": "xvirus"}, {"author": "0x7c6A9f9f9f1a67774999FF0e26ffdBa2c9347eeB", "bid": 62500000000000000, "mask": true, "metadata": "infected with EICAR Test File (NOT a Virus!)", "verdict": true, "engine": "drweb"}, {"author": "0x0457C40dBA29166c1D2485F93946688C1FC6Cc58", "bid": 62500000000000000, "mask": true, "metadata": "", "verdict": false, "engine": "lionic"}], "bounty_guid": "dee1769b-0428-4e98-a39d-aa1c230435bf", "bounty_status": "Settled", "failed": false, "filename": "eicar", "hash": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267", "result": true, "size": 69, "votes": [{"arbiter": "0xdC6a0F9C3AF726Ba05AaC14605Ac9B3b958512d7", "vote": true, "engine": "clamav-arbiter"}, {"arbiter": "0x2E03565b735E2343F7F0501A7772A42B1C0E8893", "vote": true, "engine": "psarbiter"}, {"arbiter": "0x1f50Cf288b5d19a55ac4c6514e5bA6a704BD03EC", "vote": false, "engine": "hatchingarb"}], "window_closed": true}], "forced": false, "status": "Duplicate", "uuid": "39b04176-51eb-4431-82d0-a0a3176164f0"}]

$ polyswarm download test/ 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
Downloaded 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267: test/131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267

$ polyswarm rescan 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
Scan report for GUID 46a112f2-a368-4b59-96b0-0dffac5306a6
=========================================================
Report for file 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267, hash: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
        lionic: Malicious, metadata: {"infections": [{"path": "C:/Windows/TEMP/polyswarm-artifactn8mjdwm9", "time": "2019/02/21 20:04:37", "name": "Test.File.EICAR.y!c", "location": "polyswarm-artifactn8mjdwm9"}]}
        ikarus: Malicious, metadata: EICAR-Test-File
        clamav-engine: Malicious, metadata: Eicar-Test-Signature
        drweb: Malicious, metadata: infected with EICAR Test File (NOT a Virus!)
        xvirus: Unknown/failed to respond
        tachyon: Clean
        nanoav: Malicious, metadata: {"infections": [{"name": "Marker.Dos.EICAR-Test-File.dyb"}]}
        zillya: Malicious, metadata: Status:Infected EICAR.TestFile
        k7-engine: Malicious, metadata: Trojan ( 000139291 )

```

For information regarding the JSON format, please see [API.md](https://github.com/polyswarm/polyswarm-api/blob/master/API.md).

## Questions? Problems?

File a ticket or email us at `info@polyswarm.io`.
