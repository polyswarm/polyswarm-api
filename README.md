# polyswarm-api
An interface to the public and private PolySwarm APIs.


## Installation

`pip install polyswarm-api`

## Usage

```python
import polyswarm_api

api_key = "0bee8e13f4300ed2c904caa9ea6cb180ec2524cfa0339e576235abbf62032327"

api = polyswarm_api.PolyswarmAPI(key=api_key)

results = api.scan_directory("/path/to/directory")

results = api.scan_file("/path/to/file")

results = api.scan_hash("14ef23b8c5d06c0bf2d5a4b497a5fae11994c97ec012ed57c7d34178ee9953db")

results = api.scan_hashes(["14ef23b8c5d06c0bf2d5a4b497a5fae11994c97ec012ed57c7d34178ee9953db"])
```

## Questions? Problems?

File a ticket or email us at `info@polyswarm.io`.