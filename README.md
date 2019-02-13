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

api_key = "0bee8e13f4300ed2c904caa9ea6cb180ec2524cfa0339e576235abbf62032327"

api = polyswarm_api.PolyswarmAPI(key=api_key)

results = api.scan_directory("/path/to/directory")

results = api.scan_file("/path/to/file")

results = api.scan_hash("14ef23b8c5d06c0bf2d5a4b497a5fae11994c97ec012ed57c7d34178ee9953db")

results = api.scan_hashes(["14ef23b8c5d06c0bf2d5a4b497a5fae11994c97ec012ed57c7d34178ee9953db"])
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
  lookup  lookup UUID(s)
  scan    scan files/directories
  search  search for hash

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
$
```

For information regarding the JSON format, please see [API.md](https://github.com/polyswarm/polyswarm-api/blob/master/API.md).

## Questions? Problems?

File a ticket or email us at `info@polyswarm.io`.
