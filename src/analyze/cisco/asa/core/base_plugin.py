from abc import abstractmethod
from src.analyze.common.base_plugin import BasePlugin
from src.devices.common.base_parser import BaseDeviceParser


class ASAPlugin(BasePlugin):

    def __init__(self):
        super().__init__()

    @abstractmethod
    def analyze(self, parser: BaseDeviceParser) -> None:
        pass
