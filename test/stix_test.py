import pytest
from pathlib import Path
import json
import stix2
from polyswarm_api.resources import ArtifactInstance
from polyswarm_api.formatters import StixEncoder

env = stix2.Environment(store=stix2.MemoryStore())

def fixture_path(*parts):
    return Path(__file__).parent.joinpath('fixtures', *parts)

@pytest.fixture(params=['ArtifactInstance1.json', 'ArtifactInstance2.json'])
def artifact_instance(request):
    return ArtifactInstance(json.loads(fixture_path('resources', request.param).read_text()))

def test_stix_encode_artifact(artifact_instance):
    bundle = stix2.v21.bundle.Bundle(objects=StixEncoder().encode(artifact_instance))
    stix_fixture_path = fixture_path('stix', artifact_instance.sha256).with_suffix('.json')
    assert env.semantically_equivalent(bundle, stix2.parse(stix_fixture_path.read_text())) == 0
