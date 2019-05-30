import aiohttp
import asyncio
import logging


class EngineResolver(object):

    def __init__(self, api_addr):
        self.logger = None
        self.api_addr = api_addr
        self.engine_map = None
        self.run()

    @classmethod
    def get_logger_name(cls):
        return cls.__name__

    def get_engine_name(self, eth_pub):
        return self.engine_map.get(eth_pub.lower(), eth_pub) if self.engine_map is not None else ''

    async def get_engines(self):
        try:
            self.logger.debug("Begin engine name polling")
            headers = {'content-type': 'application/json'}
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(f'{self.api_addr}/microengines/list') as response:
                    if response.status // 100 == 2:
                        result = await response.json()
                        engines_results = result.get('results', [])
                        self.engine_map = dict([(engine.get('address'), engine.get('name')) for engine in engines_results])
                        self.logger.debug(f'engine_map={self.engine_map}')
                    else:
                        self.engine_map = dict()
                        self.logger.warning('unable to get microengine information')
        except Exception as e:
            self.logger.exception('error pulling engine data from portal backend')

    def run(self):
        if self.logger is None:
            self.logger = logging.getLogger(self.get_logger_name())

        l = asyncio.get_event_loop()
        l.create_task(self.get_engines())
