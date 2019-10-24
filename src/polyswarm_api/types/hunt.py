import datetime

from .base import BasePSType, BasePSJSONType
from ..exceptions import InvalidArgument, InvalidYaraRules, NotImportedException
from .schemas import hunt
from .artifact import Artifact
from . import date

try:
    import yara
except ImportError:
    yara = None


class YaraRuleset(BasePSType):
    def __init__(self, ruleset, path=None, polyswarm=None):
        super(YaraRuleset, self).__init__(polyswarm)

        if not (path or ruleset):
            raise InvalidArgument("Must provide artifact content, either via path or content argument")

        if ruleset:
            self.ruleset = ruleset
        else:
            self.ruleset = open(path, "r").read()

    def validate(self):
        if not yara:
            raise NotImportedException("Cannot validate rules locally without yara-python")

        try:
            yara.compile(source=self.ruleset)
        except yara.SyntaxError as e:
            raise InvalidYaraRules(*e.args)

        return True


class HuntStatus(BasePSJSONType):
    SCHEMA = hunt.hunt_status

    def __init__(self, json, polyswarm=None):
        super(HuntStatus, self).__init__(json, polyswarm)

        # active only present for live hunts
        self.active = json.get('active', '')
        self.created = date.parse_date(json['created'])
        self.id = json['id']
        self.results = list(sorted([HuntMatch(match, polyswarm) for match in json['results']],
                                   key=lambda x: x.created, reverse=True)) if json['results'] else []
        self.total = json.get('total', 0)
        self.status = json['status']

    def __len__(self):
        return len(self.results)

    def __getitem__(self, i):
        return self.results[i]

    def __setitem__(self, key, value):
        self.results[key] = value


class HuntMatch(BasePSJSONType):
    SCHEMA = hunt.hunt_result

    def __init__(self, json, polyswarm=None):
        super(HuntMatch, self).__init__(json, polyswarm)

        self.rule_name = json['rule_name']
        self.tags = json['tags']
        self.artifact = Artifact(json['artifact'], polyswarm)
        self.created = date.parse_date(json['created']) if 'created' in json else datetime.datetime.now()


class Hunt(BasePSJSONType):
    SCHEMA = hunt.hunt_submission

    def __init__(self, json, polyswarm=None):
        super(Hunt, self).__init__(json, polyswarm)
        self.hunt_id = json['hunt_id']

    @classmethod
    def from_id(cls, hunt_id, polyswarm=None):
        return cls({'hunt_id': hunt_id}, polyswarm)


class LiveHunt(Hunt):
    pass


class HistoricalHunt(Hunt):
    pass
