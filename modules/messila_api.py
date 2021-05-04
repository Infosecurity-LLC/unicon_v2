import logging
import requests
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import json

urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(level='DEBUG')
logger = logging.getLogger(__name__)


class MessilaApiClient:
    def __init__(self, api_url, login, password, verify=False):
        self.__api_url = api_url
        self.__login = login
        self.__password = password
        self.__verify = verify
        self.__s = requests.Session()

    def status(self):
        return requests.get(url='{}/status'.format(self.__api_url), verify=self.__verify)

    def send_event(self, event_data):
        if 'event_type' not in event_data:
            logger.error('Не определён тип события! {}'.format(event_data))
            return False

        res = self.__s.post(url='{}/incident/create/{}'.format(self.__api_url, event_data.get('common_type')),
                            headers={'Content-type': 'application/json', 'Accept': 'application/json'},
                            auth=(self.__login, self.__password),
                            verify=self.__verify,
                            data=json.dumps(event_data))
        if res.status_code != 200:
            logger.error('Событие не было отправлено status_code: [{}] - {}\n{}'.format(res.status_code, event_data,
                                                                                        res.encoding))
            return False
        logger.info('Событие успешно отправлено {}'.format(event_data))
        return True
