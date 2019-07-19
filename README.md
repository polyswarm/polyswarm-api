<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [polyswarm-api](#polyswarm-api)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Use the provided CLI](#use-the-provided-cli)
      - [Configuration](#configuration)
      - [Perform Scans](#perform-scans)
      - [Perform Searches](#perform-searches)
      - [Lookup UUIDs](#lookup-uuids)
      - [Download Files](#download-files)
      - [Perform Rescans](#perform-rescans)
    - [Use the library:](#use-the-library)
      - [Create an API Client](#create-an-api-client)
      - [Perform Scans](#perform-scans-1)
      - [Perform Searches](#perform-searches-1)
        - [Metadata Terms](#metadata-terms)
        - [Allowed Query Searches](#allowed-query-searches)
          - [Query String](#query-string)
          - [Check If Field Exists](#check-if-field-exists)
          - [Range Query](#range-query)
          - [Terms (Array) Query](#terms-array-query)
      - [Download Files](#download-files-1)
      - [Perform Hunts](#perform-hunts)
      - [Perform Rescans](#perform-rescans-1)
      - [Get a Stream](#get-a-stream)
  - [Questions? Problems?](#questions-problems)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# polyswarm-api

An interface to the public and private PolySwarm APIs.

Supports python3.5 >= 3.5.4 and python3.6 >= 3.6.5

## Installation

From PyPI:

    pip install polyswarm-api

From source:

    python3 setup.py install

## Usage

### Use the provided CLI

#### Configuration

```bash
$ export POLYSWARM_API_KEY=<Your API key from polyswarm.network>
$ export POLYSWARM_COMMUNITY=lima
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
  download    download file(s)
  historical  interact with historical scans
  live        interact with live scans
  lookup      lookup UUID(s)
  rescan      rescan files(s) by hash
  scan        scan files/directories
  search      search for hash or query
  stream      access the polyswarm file stream
```

#### Perform Scans

```bash
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

$ polyswarm url https://www.XXXXXX.XXXX/admin.php?f=1.gif
Scan report for GUID 550bcbfe-7d75-4de0-8d23-8b490e7ee58b
=========================================================
Report for file admin.php?f=1.gif, hash: c9d2152432e5ed53513c510b5ce94557313af965ba93f7819651542408344dae
	Trustlook: Malicious, metadata: [{'malware_family': 'Malware', 'scanner': {'environment': {'operating_system': 'Linux', 'architecture': 'x86_64'}}}]
```

#### Perform Searches

```bash
$ polyswarm -o /tmp/test.txt search hash 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
$ cat /tmp/test.txt
Found 1 matches to the search query.
Search results for sha256=131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
File 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
	File type: mimetype: text/plain, extended_info: EICAR virus test files
	SHA256: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
	SHA1: cf8bd9dfddff007f75adf4c2be48005cea317c62
	MD5: 69630e4574ec6798239b091cda43dca0
	Observed countries: US,PR
	Observed filenames: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267,eicar.com.txt,eicar.txt
```

```bash
$ polyswarm -o /tmp/test.txt search metadata "strings.domains:en.wikipedia.org AND exiftool.ZipFileName:AndroidManifest.xml AND exiftool.ZipRequiredVersion:>19"
$ cat /tmp/test.txt | more
Found 18 matches to the search query.
Search results for {'query': {'query_string': {'query': 'strings.domains:en.wikipedia.org AND exift
ool.ZipFileName:AndroidManifest.xml AND exiftool.ZipRequiredVersion:>19'}}}
File 1d38780c2327086816d0a87d878d57b943d6ad5109b9389b5d5ffe3f9065698b
	File type: mimetype: application/java-archive, extended_info: Java archive data (JAR)
	SHA256: 1d38780c2327086816d0a87d878d57b943d6ad5109b9389b5d5ffe3f9065698b
	SHA1: 76f5b2c6abbd6b30dc00fbe797001bf7247f423b
	MD5: 12a1028e90696d9f3926ac3ab150950c
	First seen: Sun, 24 Mar 2019 15:27:32 GMT
	Observed countries: 
	Observed filenames: 1d38780c2327086816d0a87d878d57b943d6ad5109b9389b5d5ffe3f9065698b


File d8e6ac2884597021479796d252fcd61dbbfd71f7c07af54d71478af377e0bfb9
	File type: mimetype: application/java-archive, extended_info: Java archive data (JAR)
	SHA256: d8e6ac2884597021479796d252fcd61dbbfd71f7c07af54d71478af377e0bfb9
	SHA1: a5b267cd66d0da885d252b279d28cb887f8b901c
	MD5: bb0dd7f93ef2eaacfde18d07909fac0b
	First seen: Sun, 31 Mar 2019 08:58:17 GMT
	Observed countries: 
	Observed filenames: d8e6ac2884597021479796d252fcd61dbbfd71f7c07af54d71478af377e0bfb9


File 041044068eb8295a4d80786c3f55c77c641b6f3eb33187bbf504aa923ec5db78
	File type: mimetype: application/java-archive, extended_info: Java archive data (JAR)
	SHA256: 041044068eb8295a4d80786c3f55c77c641b6f3eb33187bbf504aa923ec5db78
	SHA1: 5ab68f339ddf9d8701d2c3947cc0596652b92cb0
	MD5: c93a8476c16cc7e044be305b71fe1b1f
	First seen: Wed, 27 Mar 2019 07:02:24 GMT
	Observed countries: 
--More--
```

#### Lookup UUIDs

```bash
$ polyswarm -vvv -o /tmp/test.json --fmt json lookup 39b04176-51eb-4431-82d0-a0a3176164f0
DEBUG:root:Creating API instance: api_key:<redacted>
DEBUG:asyncio:Using selector: EpollSelector

$ cat /tmp/test.json
[{"files": [{"assertions": [{"author": "0x1EdF29c0977aF06215032383F93deB9899D90118", "bid": 62500000000000000, "mask": true, "metadata": "", "verdict": false, "engine": "tachyon"}, {"author": "0x2b4C240B376E5406C5e2559C27789d776AE97EFD", "bid": 62500000000000000, "mask": true, "metadata": "{\"infections\": [{\"name\": \"Marker.Dos.EICAR-Test-File.dyb\"}]}", "verdict": true, "engine": "nanoav"}, {"author": "0xf6019C1f057D26FFB2b41C221E0DB4Ef88931C86", "bid": 62500000000000000, "mask": true, "metadata": null, "verdict": null, "engine": "zillya"}, {"author": "0x3750266F07E0590aA16e55c32e08e48878010f8f", "bid": 62500000000000000, "mask": true, "metadata": "Eicar-Test-Signature", "verdict": true, "engine": "clamav-engine"}, {"author": "0xbE0B3ec289aaf9206659F8214c49D083Dc1a9E17", "bid": 62500000000000000, "mask": true, "metadata": "Trojan ( 000139291 )", "verdict": true, "engine": "k7-engine"}, {"author": "0xA4815D9b8f710e610E8957F4aD13F725a4331cbB", "bid": 62500000000000000, "mask": true, "metadata": "EICAR-Test-File", "verdict": true, "engine": "ikarus"}, {"author": "0x59Af39803354Bd08971Ac8e7C6dB7410a25Ab8DA", "bid": 62500000000000000, "mask": true, "metadata": "", "verdict": true, "engine": "xvirus"}, {"author": "0x7c6A9f9f9f1a67774999FF0e26ffdBa2c9347eeB", "bid": 62500000000000000, "mask": true, "metadata": "infected with EICAR Test File (NOT a Virus!)", "verdict": true, "engine": "drweb"}, {"author": "0x0457C40dBA29166c1D2485F93946688C1FC6Cc58", "bid": 62500000000000000, "mask": true, "metadata": "", "verdict": false, "engine": "lionic"}], "bounty_guid": "dee1769b-0428-4e98-a39d-aa1c230435bf", "bounty_status": "Settled", "failed": false, "filename": "eicar", "hash": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267", "result": true, "size": 69, "votes": [{"arbiter": "0xdC6a0F9C3AF726Ba05AaC14605Ac9B3b958512d7", "vote": true, "engine": "clamav-arbiter"}, {"arbiter": "0x2E03565b735E2343F7F0501A7772A42B1C0E8893", "vote": true, "engine": "psarbiter"}, {"arbiter": "0x1f50Cf288b5d19a55ac4c6514e5bA6a704BD03EC", "vote": false, "engine": "hatchingarb"}], "window_closed": true}], "forced": false, "status": "Duplicate", "uuid": "39b04176-51eb-4431-82d0-a0a3176164f0"}]
```

#### Download Files

```bash
$ polyswarm download test/ 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
Downloaded 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267: test/131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
```

#### Perform Rescans

```bash
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

### Use the library:

#### Create an API Client

```python
import polyswarm_api

api_key = "317b21cb093263b701043cb0831a53b9"

api = polyswarm_api.PolyswarmAPI(key=api_key)
```

**Note:** You will need to get your own API key from [`polyswarm.network/profile/apiKeys`](https://polyswarm.network/profile/apiKeys)

#### Perform Scans

```python
results = api.scan_directory("/path/to/directory")

results = api.scan_file("/path/to/eicar")

results = api.scan_url("http://bad.com")
```

#### Perform Searches

```python
results = api.search_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

results = api.search_hashes(["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"])

query = { "query": {
                "exists": {
                    "field": "lief.libraries"
                }
            }
        }
results = api.search_query(query)

```

##### Metadata Terms
The following is a non-exhaustive list of the terms currently supported by PolySwarm.
When searching, each nested level would be separated by `.`, e.g. `pefile.imphash`.
Names of fields *are case-sensitive* so take care to specify them correctly. The following list is non-exhaustive.
If there are more fields or tools you would like to see, please get in touch at [info@polyswarm.io](mailto:info@polyswarm.io).

* `lief` - curated `lief` output
    * `has_nx`
    * `is_pie`
    * `libraries` - list of imported libraries
    * `entrypoint` - entrypoint in decimal
    * `virtual_size` - virtual size in decimal
    * `exported_functions` - list of exported functions
    * `imported_functions` - list of imported functions

* `pefile` - curated `pefile` output
    * `is_dll` - boolean
    * `is_exe` - boolean
    * `exports` - exported functions
    * `imphash` - `imphash` of the file
    * `imports` - dictionary of imports in format `dllname: [list, of, functions]`
    * `uses_cfg` - boolean
    * `uses_dep` - boolean
    * `uses_seh` - boolean
    * `compile_date` - boolean
    * `has_import_table` - boolean
    * `has_export_table` - boolean
    * `is_probably_packed` - boolean
    * `warnings` - warnings from pefile parser
    
* `exiftool` - `exiftool` output (from `exiftool -j`)
    * `MIMEType` - mimetype of the file
    * `InternalName` - internal name extracted from executable
    * `OriginalFileName` - original name of the file
    * `Author` - author of the file
    * `Title` - title of the file
    * `Subject` - subject of the file
    * `LanguageCode` - language used by executable (e.g. 'English (U.S.)')
    * `CharacterSet` - character set of file
    * `Language` - language of file (e.g. 'en-GB')
    * `ModifyDate` - last modified time string from document
    * `CreateDate` - creation time string from document
    * many more; view `exiftool` documentation for more info.

* `strings` - interesting statically-extracted strings
    * `domains` - observed domains
    * `urls` - URLs (including things like emails)
    * `ipv4` - IPV4 addresses
    * `ipv6` - IPV6 addresses

##### Allowed Query Searches

For query search, only a sub-set of [Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/6.7/) queries are allowed at the moment.

They are only allowed in the following simple form (not in the complete form with all other attributes) for security reasons.

To make command line searching easier, the default input format for the CLI is a query field that will be wrapped into a [JSON `query_string` request](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html).
This is likely sufficient for most queries.
Do note: some characters, like backslashes, must be escaped with a backslash.

###### Query String

```json
{
    "query": {
      "query_string": {
            "query": "this AND that OR something:>10"
        }
    }
}
```

###### Check If Field Exists

```json
{
    "query": {
        "exists": {
            "field": "lief.libraries"
        }
    }
}

```

**Note:** [Elasticsearch Exists Query](https://www.elastic.co/guide/en/elasticsearch/reference/6.7/query-dsl-exists-query.html).


###### Range Query

```json
{
    "query": {
        "range": {
            "age": {
                "gte": 10,
                "lte": 20
            }
        }
    }
}

```

**Note:** [Elasticsearch Range Query](https://www.elastic.co/guide/en/elasticsearch/reference/6.7/query-dsl-range-query.html). These are specially interesting for date fields. You will find a reference on date math [here](https://www.elastic.co/guide/en/elasticsearch/reference/6.4/query-dsl-range-query.html).

```

**Note:** [Elasticsearch Query String](https://www.elastic.co/guide/en/elasticsearch/reference/6.7/query-dsl-query-string-query.html).


###### Simple Query String

```json
{
    "query": {
        "simple_query_string": {
            "query": "\"fried eggs\" +(eggplant | potato) -frittata",
            "fields": ["title^5", "body"],
            "default_operator": "and"
        }
    }
}
```

**Note:** [Elasticsearch Simple Query String](https://www.elastic.co/guide/en/elasticsearch/reference/6.7/query-dsl-simple-query-string-query.html).

###### Terms (Array) Query

```json
{
    "query": {
        "terms": {
            "user": ["kimchy", "elasticsearch"]
        }
    }
}
```

**Note:** [Elasticsearch Terms Query](https://www.elastic.co/guide/en/elasticsearch/reference/6.7/query-dsl-terms-query.html).

#### Download Files

```python
results = api.download_file("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "test/")

results = api.rescan_file("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

results = api.new_live_hunt(open("eicar.yara").read()) 

results = api.get_live_results(hunt_id=results['result']['hunt_id'])

results = api.new_historical_hunt(open("eicar.yara").read()) 

results = api.get_historical_results(hunt_id=results['result']['hunt_id'])

results = api.get_stream(destination_dir="/my/malware/path")
```

#### Perform Hunts

```python
results = api.new_live_hunt(open("eicar.yara").read()) 

results = api.get_live_results(hunt_id=results['result']['hunt_id'])

results = api.new_historical_hunt(open("eicar.yara").read()) 

results = api.get_historical_results(hunt_id=results['result']['hunt_id'])
```

#### Perform Rescans

```python
results = api.rescan_file("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
``````

#### Get a Stream

```python
results = api.get_stream(destination_dir="/my/malware/path")
```

## Questions? Problems?

File a ticket or email us at `info@polyswarm.io`.
