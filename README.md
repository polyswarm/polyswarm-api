<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [polyswarm-api](#polyswarm-api)
  - [Dependencies](#dependencies)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Use the provided CLI](#use-the-provided-cli)
      - [Configuration](#configuration)
      - [Perform Scans](#perform-scans)
      - [Perform Searches](#perform-searches)
      - [Lookup UUIDs](#lookup-uuids)
      - [Download Files](#download-files)
      - [Perform Rescans](#perform-rescans)
      - [Chain commands](#chain-commands)
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

Supports Python 2.7 and greater.

## Dependencies

You may need to install your platforms' equivalent `python-dev` package.

## Installation

From PyPI:

    pip install polyswarm-api

From source:

    python setup.py install

## Usage

### Use the provided CLI

#### Configuration

```bash
$ export POLYSWARM_API_KEY=<Your API key from polyswarm.network>
$ export POLYSWARM_COMMUNITY=lima
# for tab completion
$ eval "$(_POLYSWARM_COMPLETE=source polyswarm)"
$ polyswarm
Usage: polyswarm [OPTIONS] COMMAND [ARGS]...

  This is a PolySwarm CLI client, which allows you to interact directly with
  the PolySwarm network to scan files, search hashes, and more.

Options:
  -a, --api-key TEXT              Your API key for polyswarm.network
                                  (required)
  -u, --api-uri TEXT              The API endpoint (ADVANCED)
  -o, --output-file FILENAME      Path to output file.
  --output-format, --fmt [text|json|sha256|sha1|md5]
                                  Output format. Human-readable text or JSON.
  --color / --no-color            Use colored output in text mode.
  -v, --verbose
  -c, --community TEXT            Community to use.
  --advanced-disable-version-check / --advanced-enable-version-check
                                  Enable/disable GitHub release version check.
  -h, --help                      Show this message and exit.

Commands:
  download    download file(s)
  historical  interact with historical scans)
  live        interact with live scans
  lookup      lookup UUID(s)
  rescan      rescan files(s) by hash
  scan        scan files/directories
  search      interact with PolySwarm search api
  stream      access the polyswarm file stream
  url         scan url
```

#### Perform Scans

```bash
$ polyswarm scan /tmp/eicar
Report for artifact eicar, hash: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
        16 out of 19 engines reported this as malicious
        XVirus: Malicious, metadata: {'malware_family': '', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'vendor_version': '3.0.2.0', 'version': '0.2.0'}}
        Trustlook: Clean
        Virusdie: Malicious, metadata: {'malware_family': 'EICAR.TEST', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}, 'vendor_version': '1.3.0', 'version': '0.3.0'}}
        Ikarus: Malicious, metadata: {'malware_family': 'EICAR-Test-File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}, 'signatures_version': '13.10.2019 18:20:55 (102021)', 'vendor_version': '5.2.9.0', 'version': '0.2.0'}}
        Nucleon: Clean
        Alibaba: Malicious, metadata: {'malware_family': 'Virus:Any/EICAR_Test_File.534838ff', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}}, 'type': 'eicar'}
        Jiangmin: Malicious, metadata: {'malware_family': 'Find Virus EICAR-Test-File in C:\\Users\\ContainerAdministrator\\AppData\\Local\\Temp\\polyswarm-artifact_2k4sehx', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'signatures_version': '', 'vendor_version': '16.0.100 ', 'version': '0.2.0'}}
        K7: Malicious, metadata: {'malware_family': 'Trojan ( 000139291 )', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'signatures_version': '11.66.31997|12/Sep/2019', 'vendor_version': '15.2.0.42', 'version': '0.2.0'}}
        ClamAV: Malicious, metadata: {'malware_family': 'Eicar-Test-Signature', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}, 'vendor_version': 'ClamAV 0.100.3/25601/Sun Oct 13 08:51:55 2019\n'}}
        Quick Heal: Malicious, metadata: {'malware_family': 'EICAR.TestFile', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'signatures_version': '09 September, 2019', 'version': '0.1.0'}}
        Rising: Malicious, metadata: {'malware_family': 'Virus.EICAR_Test_File!8.D9E', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}
        NanoAV: Malicious, metadata: {'malware_family': 'Marker.Dos.EICAR-Test-File.dyb', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'signatures_version': '0.14.32.16015|1568318271000', 'vendor_version': '1.0.134.90395', 'version': '0.1.0'}}
        0xBAFcaF4504FCB3608686b40eB1AEe09Ae1dd2bc3: Malicious, metadata: {'malware_family': 'infected with EICAR Test File (NOT a Virus!)', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}, 'signatures_version': 'Core engine version: 7.00.41.07240\nVirus database timestamp: 2019-Oct-13 22:55:51\nVirus database fingerprint: 8AC41842F33C025F71031B23CD5E104B\nVirus databases loaded: 170\nVirus records: 8212364\nAnti-spam core is not loaded\nLast successful update: 2019-Oct-14 00:56:00\nNext scheduled update: 2019-Oct-14 01:26:00\n', 'vendor_version': 'drweb-ctl 11.1.2.1907091642\n', 'version': '0.3.0'}}
        Lionic: Malicious, metadata: {'malware_family': '{"infections": [{"name": "Test.File.EICAR.y!c", "location": "polyswarm-artifactqlel80c6", "path": "C:/Users/ContainerAdministrator/AppData/Local/Temp/polyswarm-artifactqlel80c6", "time": "2019/10/14 01:10:11"}]}', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}}}
        SecureAge: Malicious, metadata: {'malware_family': '', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'signatures_version': '5.73', 'version': '0.3.0'}}
        VenusEye: Malicious, metadata: {'malware_family': '', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}, 'version': '0.1.0'}}
        Tachyon: Malicious, metadata: {'malware_family': 'EICAR-Test-File', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'vendor_version': '2018.11.28.1', 'version': '0.1.0'}}
        Qihoo 360: Malicious, metadata: {'malware_family': 'qex.eicar.gen.gen', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}}}
        ZeroCERT: Clean

$ polyswarm url https://google.com
Report for artifact url, hash: 05046f26c83e8c88b3ddab2eab63d0d16224ac1e564535fc75cdceee47a0938d
        All 5 engines reported this as benign or did not respond
        Virusdie: Clean
        Trustlook: Clean
        Nucleon: Clean
        Cyradar: Clean
        ZeroCERT: Clean
        Scan permalink: https://polyswarm.network/scan/results/1377b0e4-d54a-41b8-87bf-a0885d67cf3c
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
        First seen: Wed, 22 May 2019 15:25:47 GMT
        Observed countries: PR,US
        Observed filenames: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267,eicar.com,eicar.txt,cf8bd9dfddff007f75adf4c2be48005cea317c62,eicar.com.txt
        Scan permalink: https://polyswarm.network/scan/results/8f51790a-4e30-48ad-b0a2-036c7306168f
        Detections: 16/19 engines reported malicious
```

```bash
$ polyswarm -o /tmp/test.txt search metadata "strings.domains:en.wikipedia.org AND exiftool.ZipFileName:AndroidManifest.xml AND exiftool.ZipRequiredVersion:>19"
$ cat /tmp/test.txt | more
Found 1000 matches to the search query.
Search results for {'query': {'query_string': {'query': 'strings.domains:en.wikipedia.org AND exiftool.ZipFileName:AndroidManifest.xml'}}}
File 55f9d374e0d16ecaa047f2af9f2dcbb0a6576847caee0a2cbdc36a079961a991 
        File type: mimetype: application/x-dosexec, extended_info: PE32 executable (GUI) Intel 80386, for MS Windows
        SHA256: 55f9d374e0d16ecaa047f2af9f2dcbb0a6576847caee0a2cbdc36a079961a991
        SHA1: 4a0da13003a36fc299ea5c7ebd54d59e42854f22
        MD5: ba72c9d80b336ae481a3eceaace1844e                                                                                 
        First seen: Mon, 02 Sep 2019 13:48:06 GMT
        Observed countries: US                                           
        Observed filenames: 55f9d374e0d16ecaa047f2af9f2dcbb0a6576847caee0a2cbdc36a079961a991
        Scan permalink: https://polyswarm.network/scan/results/9c50c2ca-31a8-42cd-b067-b864eff57409
        Detections: 12/19 engines reported malicious
--More--
```

#### Lookup UUIDs

```bash
$ polyswarm -vvv -o /tmp/test.json --fmt json lookup ac331689-c4a1-400c-be79-98268c182c88
DEBUG:root:Creating API instance: api_key:<redacted>, api_uri:https://api.polyswarm.network/v1
DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): api.polyswarm.network:443
DEBUG:urllib3.connectionpool:https://api.polyswarm.network:443 "GET /v1/consumer/lima/uuid/ac331689-c4a1-400c-be79-98268c182c88 HTTP/1.1" 200 610
DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): api.polyswarm.network:443
DEBUG:urllib3.connectionpool:https://api.polyswarm.network:443 "GET /v1/microengines/list HTTP/1.1" 200 1887
$ cat /tmp/test.json
{"files": [{"assertions": [{"author": "0x80Ed773972d8BA0A4FacF2401Aca5CEba52F76dc", "bid": 500000000000000000, "mask": true, "metadata": {"malware_family": "", "scanner": {"environment": {"architecture": "x86_64", "operating_system": "Linux"}, "vendor_version": "", "version": "0.1.0"}}, "verdict": false, "engine_name": "Nucleon"}, {"author": "0x8d80CEe474b9004949Cf7e4BfA28460AC8e370a1", "bid": 500000000000000000, "mask": true, "metadata": {"malware_family": "", "scanner": {"environment": {"architecture": "x86_64", "operating_system": "Linux"}, "version": "0.3.0"}}, "verdict": false, "engine_name": "Virusdie"}, {"author": "0xF598F7dA0D00D9AD21fb00663a7D62a19D43Ea61", "bid": 500000000000000000, "mask": true, "metadata": {"malware_family": "Search engine", "scanner": {"environment": {"architecture": "x86_64", "operating_system": "Linux"}, "vendor_version": "2", "version": "0.1.0"}}, "verdict": false, "engine_name": "Trustlook"}, {"author": "0x8434434991A61dAcE1544a7FC1B0F8d83523B778", "bid": 500000000000000000, "mask": true, "metadata": {"malware_family": "", "scanner": {"environment": {"architecture": "x86_64", "operating_system": "Linux"}, "vendor_version": "", "version": "0.1.0"}}, "verdict": false, "engine_name": "Cyradar"}, {"author": "0xdCc9064325c1aa24E08182676AD23B3D78b39E05", "bid": 500000000000000000, "mask": true, "metadata": {"malware_family": "", "scanner": {"environment": {"architecture": "x86_64", "operating_system": "Linux"}, "vendor_version": "1.1", "version": "0.1.0"}}, "verdict": false, "engine_name": "ZeroCERT"}], "bounty_guid": "423a680a-ebf5-41a1-ba66-c64a84924091", "bounty_status": "Bounty Settled", "failed": false, "filename": "url", "hash": "05046f26c83e8c88b3ddab2eab63d0d16224ac1e564535fc75cdceee47a0938d", "result": null, "size": 18, "submission_guid": "ac331689-c4a1-400c-be79-98268c182c88", "votes": [], "window_closed": true}], "forced": false, "status": "Bounty Settled", "uuid": "ac331689-c4a1-400c-be79-98268c182c88"}
```

#### Download Files

```bash
$ polyswarm download test/ 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
Successfully downloaded artifact 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267 to /home/user/test/131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
```

#### Perform Rescans

```bash
$ polyswarm rescan 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
Report for artifact 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267, hash: 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
        17 out of 20 engines reported this as malicious
        VenusEye: Malicious, metadata: {'malware_family': '', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}, 'version': '0.1.0'}}
        K7: Malicious, metadata: {'malware_family': 'Trojan ( 000139291 )', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'signatures_version': '11.66.31997|12/Sep/2019', 'vendor_version': '15.2.0.42', 'version': '0.2.0'}}
        Jiangmin: Malicious, metadata: {'malware_family': 'Find Virus EICAR-Test-File in C:\\Users\\ContainerAdministrator\\AppData\\Local\\Temp\\polyswarm-artifactztoecu5h', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'signatures_version': '', 'vendor_version': '16.0.100 ', 'version': '0.2.0'}}
        Virusdie: Malicious, metadata: {'malware_family': 'EICAR.TEST', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}, 'vendor_version': '1.3.0', 'version': '0.3.0'}}
        Trustlook: Clean
        0xBAFcaF4504FCB3608686b40eB1AEe09Ae1dd2bc3: Malicious, metadata: {'malware_family': 'infected with EICAR Test File (NOT a Virus!)', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}, 'signatures_version': 'Core engine version: 7.00.41.07240\nVirus database timestamp: 2019-Oct-14 00:10:21\nVirus database fingerprint: 95CC1F8E066874DCF48E898334572198\nVirus databases loaded: 170\nVirus records: 8212567\nAnti-spam core is not loaded\nLast successful update: 2019-Oct-14 01:56:03\nNext scheduled update: 2019-Oct-14 02:26:03\n', 'vendor_version': 'drweb-ctl 11.1.2.1907091642\n', 'version': '0.3.0'}}
        Nucleon: Clean
        Alibaba: Malicious, metadata: {'malware_family': 'Virus:Any/EICAR_Test_File.534838ff', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}}, 'type': 'eicar'}
        NanoAV: Malicious, metadata: {'malware_family': 'Marker.Dos.EICAR-Test-File.dyb', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'signatures_version': '0.14.32.16015|1568318271000', 'vendor_version': '1.0.134.90395', 'version': '0.1.0'}}
        Quick Heal: Malicious, metadata: {'malware_family': 'EICAR.TestFile', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'signatures_version': '09 September, 2019', 'version': '0.1.0'}}
        Qihoo 360: Malicious, metadata: {'malware_family': 'qex.eicar.gen.gen', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}}}
        ZeroCERT: Clean
        XVirus: Malicious, metadata: {'malware_family': '', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'vendor_version': '3.0.2.0', 'version': '0.2.0'}}
        Ikarus: Malicious, metadata: {'malware_family': 'EICAR-Test-File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}, 'signatures_version': '13.10.2019 18:20:55 (102021)', 'vendor_version': '5.2.9.0', 'version': '0.2.0'}}
        ClamAV: Malicious, metadata: {'malware_family': 'Eicar-Test-Signature', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}, 'vendor_version': 'ClamAV 0.100.3/25601/Sun Oct 13 08:51:55 2019\n'}}
        SecureAge: Malicious, metadata: {'malware_family': '', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'signatures_version': '5.73', 'version': '0.3.0'}}
        Lionic: Malicious, metadata: {'malware_family': '{"infections": [{"name": "Test.File.EICAR.y!c", "location": "polyswarm-artifact52c_247x", "path": "C:/Users/ContainerAdministrator/AppData/Local/Temp/polyswarm-artifact52c_247x", "time": "2019/10/14 02:00:47"}]}', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}}}
        Antiy-AVL: Malicious, metadata: {'malware_family': 'Virus/DOS.EICAR_Test_File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}
        Tachyon: Malicious, metadata: {'malware_family': 'EICAR-Test-File', 'scanner': {'environment': {'architecture': 'AMD64', 'operating_system': 'Windows'}, 'vendor_version': '2018.11.28.1', 'version': '0.1.0'}}
        Rising: Malicious, metadata: {'malware_family': 'Virus.EICAR_Test_File!8.D9E', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}
        Scan permalink: https://polyswarm.network/scan/results/ce290fc6-77c1-4dd2-944d-2dc52b6ea722
```

For information regarding the JSON format, please see [API.md](https://github.com/polyswarm/polyswarm-api/blob/master/API.md).

#### Chain commands
Some commands in the CLI are composable using the `sha256` format option. For instance, if we wanted to download all the results matching a metadata query:

```bash
$ polyswarm --fmt sha256 search metadata 'strings.domains:malicious.com' | polyswarm download malicious -r -
Successfully downloaded artifact 131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267 to /home/user/malicious/131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267
``` 

Currently, this supports anything that takes a hash argument.

### Use the library:

#### Create an API Client

```python
from polyswarm_api.api import PolyswarmAPI

api_key = "317b21cb093263b701043cb0831a53b9"

api = polyswarm_api.PolyswarmAPI(key=api_key)
```

**Note:** You will need to get your own API key from [`polyswarm.network/profile/apiKeys`](https://polyswarm.network/profile/apiKeys)

#### Perform Scans

```python
results = api.scan_directory("/path/to/directory")

results = api.scan("/path/to/eicar")

results = api.scan_urls("http://bad.com")
```

#### Perform Searches

```python
results = api.search("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")


query = { "query": {
                "exists": {
                    "field": "lief.libraries"
                }
            }
        }
results = api.search_by_metadata(*[query])
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
results = api.download("download/", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
```

#### Perform Hunts

```python
response = api.live(open("eicar.yara").read()) 

results = api.live_results(hunt_id=response.result.id)

response = api.historical(open("eicar.yara").read()) 

results = api.historical_results(hunt_id=response.result.id)
```

#### Perform Rescans

```python
results = api.rescan("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
```

#### Get a Stream

```python
results = api.stream(destination_dir="/my/malware/path")
```

## Questions? Problems?

File a ticket or email us at `info@polyswarm.io`.
