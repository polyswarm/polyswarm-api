<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [polyswarm-api](#polyswarm-api)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Create an API Client](#create-an-api-client)
    - [Perform Scans](#perform-scans)
    - [Perform Searches](#perform-searches)
      - [Metadata Terms](#metadata-terms)
      - [Allowed Query Searches](#allowed-query-searches)
        - [Query String](#query-string)
        - [Check If Field Exists](#check-if-field-exists)
        - [Range Query](#range-query)
        - [Terms (Array) Query](#terms-array-query)
    - [Download Files](#download-files)
    - [Perform Hunts](#perform-hunts)
    - [Perform Rescans](#perform-rescans)
    - [Get a Stream](#get-a-stream)
- [Questions? Problems?](#questions-problems)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# polyswarm-api

An interface to the public and private PolySwarm APIs.
For an easy-to-use CLI tool, or as an example of how to use these APIs, please see [polyswarm-cli](https://github.com/polyswarm/polyswarm-cli)

Supports Python 2.7 and greater.

## Installation

From PyPI:

    pip install polyswarm-api

From source:

    python setup.py install

## Usage

### Create an API Client

```python
from polyswarm_api.api import PolyswarmAPI

api_key = "317b21cb093263b701043cb0831a53b9"

api = PolyswarmAPI(key=api_key)
```

**Note:** You will need to get your own API key from [`polyswarm.network/profile/apiKeys`](https://polyswarm.network/profile/apiKeys)

### Perform Scans

```python
results = api.scan_directory("/path/to/directory")

results = api.scan("/path/to/eicar")

results = api.scan_urls("http://bad.com")
```

### Perform Searches

```python
results = api.search("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")


query = { "query": {
                "exists": {
                    "field": "lief.libraries"
                }
            }
        }
results = api.search_by_metadata(query)
```

#### Metadata Terms
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

#### Allowed Query Searches

For query search, only a sub-set of [Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/6.7/) queries are allowed at the moment.

They are only allowed in the following simple form (not in the complete form with all other attributes) for security reasons.

To make command line searching easier, the default input format for the CLI is a query field that will be wrapped into a [JSON `query_string` request](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html).
This is likely sufficient for most queries.
Do note: some characters, like backslashes, must be escaped with a backslash.

##### Query String

```json
{
    "query": {
      "query_string": {
            "query": "this AND that OR something:>10"
        }
    }
}
```

##### Check If Field Exists

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


##### Range Query

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

##### Terms (Array) Query

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

### Download Files

```python
results = api.download("download/", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
```

### Perform Hunts

```python
response = api.live(open("eicar.yara").read()) 

results = api.live_results(hunt_id=response.result.id)

response = api.historical(open("eicar.yara").read()) 

results = api.historical_results(hunt_id=response.result.id)
```

### Perform Rescans

```python
results = api.rescan("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
```

### Get a Stream

```python
results = api.stream(destination_dir="/my/malware/path")
```

# Questions? Problems?

File a ticket or email us at `info@polyswarm.io`.
