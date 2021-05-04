#!/usr/bin/env python3
import logging
import time
from logging.handlers import TimedRotatingFileHandler
import threading
import os
from raven.handlers.logging import SentryHandler
from raven.conf import setup_logging
import pymongo
from pymongo import errors
import pymssql
from datetime import datetime, timedelta
from dateutil.parser import parse
from pytz import timezone
import decimal
import re
import sys
import ipaddress
from bson.objectid import ObjectId
from modules.configer import configer
from modules.pre_transformer import PreTransformer
from modules.post_transformer import PostTransformer
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import socket
from modules.db_connectors import SelectorMSSQL
from modules.db_connectors import SelectorPostgreSQL

urllib3.disable_warnings(InsecureRequestWarning)

setting = configer()
tz = timezone(setting['tz'])
logger = logging.getLogger(__name__)
logger.setLevel(setting['logging']['basic_level'])

current_dir = os.path.abspath(os.path.dirname(__file__))
os.chdir(current_dir)

if setting['logging'].get('log'):
    file_handler = TimedRotatingFileHandler(filename=setting['log'], when='D', backupCount=7, encoding='utf-8')
    file_handler.setLevel(setting['logging']['file_level'])
    file_handler.setFormatter(
        logging.Formatter('%(asctime)s - %(levelname)-10s - [in %(pathname)s:%(lineno)d]: - %(message)s'))
    logger.addHandler(file_handler)


class ContextFilter(logging.Filter):
    hostname = socket.gethostname()

    def filter(self, record):
        record.hostname = ContextFilter.hostname
        return True


stream_handler = logging.StreamHandler()
stream_handler.setLevel(setting['logging']['term_level'])
stream_handler.addFilter(ContextFilter())
stream_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(levelname)-10s - %(hostname)s - [in %(pathname)s:%(lineno)d]: - %(message)s'))
logger.addHandler(stream_handler)

sentry_url = setting.get('sentry_url')
if sentry_url:
    handler = SentryHandler(sentry_url)
    handler.setLevel(setting['logging']['sentry_level'])
    setup_logging(handler)

# MONGO ###########
mongo_host, mongo_port = setting['mongodb']['host'], setting['mongodb']['port']
mongo_lock = threading.Lock()

self_params = setting.get('self')
if not self_params:
    raise Exception('Setting error. Self params not found')


class MongoException(Exception):
    pass


class TransformationException(Exception):
    pass


class DetermineException(Exception):
    pass


class DbaseException(Exception):
    pass


class Collector:
    def __init__(self, conn_type, environment, env_alias):
        self.env_alias = env_alias
        self.conn_type = conn_type
        self.environment = environment
        self.rq = setting['sensors'][self.conn_type]['raw_query']
        self.mongo = pymongo.MongoClient(host=mongo_host, port=mongo_port)
        self.filters = setting['sensors'][self.conn_type]['filters']

    def select_events(self, last_position=None, event_id=None):
        """забрать события из базы. Возвращаем итератор с сырым событием"""
        try:
            if "db_type" in self.environment and self.environment['db_type'] == "postgresql":
                eg = SelectorPostgreSQL(self.conn_type, self.environment['external_db'])
            else:
                eg = SelectorMSSQL(self.conn_type, self.environment['external_db'])
            # eg = Selector(self.conn_type, self.environment['external_db'])
        except Exception as err:
            raise DbaseException(f'[{self.conn_type}] ошибка при взаимодействии с БД : {err}')
        if last_position:
            cur = eg.raw_query(
                self.rq['all'].format(lastposition=last_position, sensor=self.environment['external_db']['server']))
        elif event_id:
            cur = eg.raw_query(
                self.rq['by_event_id'].format(event_id=event_id, sensor=self.environment['external_db']['server']))
        else:
            logger.critical(f'[{self.conn_type}] OMG!.. what we sent in the parameters??')
            sys.exit(0)  # в теории этого не должно случиться

        vals = cur.fetchall()
        for val in vals:
            event = dict(zip(setting['sensors'][self.conn_type]['select_keys'], val))
            for k, v in event.items():
                if isinstance(v, datetime):
                    event[k] = event[k].isoformat()
                if isinstance(v, decimal.Decimal):
                    event[k] = int(event[k])
            yield event

    def define_organisation(self, event):
        """ 
        переопределение организации
        Если не удалось промапить - берём организацию из окружения
        """

        def organization_mapping_by_vsname(event, pre_org=None):
            """
             Определяем организацию по имени управляющего сервера
            :param event:
            :param pre_org: имя организации, которое возможно было промаплено ранее
                Если не удастся промапить организацию, транслируем pre_org как результат
            :return:
            """
            if not self.environment.get('organization_mapping_by_vsName') \
                    or 'organization_mapping_by_vsName' not in self.environment:
                # Если в конфиге нет данных для маппинга - не маппим
                return pre_org
            vsname = event.get('vserver')
            if vsname in self.environment.get('organization_mapping_by_vsName'):
                if self.environment['organization_mapping_by_vsName'].get(vsname) == "not_map":
                    logger.warning(
                        f'[{self.conn_type}] Обнаружены события с организацией [{vsname}] которую отказались мапить')
                    return pre_org
                logger.debug(f"[{self.conn_type}] По имени управляющего сервера событие относится к "
                             f"{vsname} - {self.environment['organization_mapping_by_vsName'].get(vsname)}")
                return self.environment['organization_mapping_by_vsName'].get(vsname)
            logger.warning(f"[{self.conn_type}] Событие по незарегистрированной организации {vsname}")
            # Если организация не промаплена по виртуальному серверу
            return pre_org

        def organization_domain_mapping(event, pre_org=None):
            """
             Определяем отганизацию по домену
            :param event:
            :param pre_org: имя организации, которое возможно было промаплено ранее
                Если не удастся промапить организацию, транслируем pre_org как результат
            :return:
            """
            if not setting.get('organization_mapping_by_domain') \
                    or 'organization_mapping_by_domain' not in setting:
                return pre_org
            domain = event.get('comp_dom')
            if domain in setting['organization_mapping_by_domain']:
                logger.debug(f"[{self.conn_type}] По домену событие относится к "
                             f"{domain} - {setting['organization_mapping_by_domain'][domain]}")
                return setting['organization_mapping_by_domain'][domain]
            return pre_org  # если нет в мапе

        org = None
        if event.get('vserver'):
            org = organization_mapping_by_vsname(event, org)
        if event.get('comp_dom') and not org:
            org = organization_domain_mapping(event, org)

        if not org and self.environment.get('organization'):
            # если не смогли ничего промаппить, ставим организацию по дефолту из конфига
            org = self.environment.get('organization')
        if not org and not self.environment.get('organization'):
            # Если и в конфиге не указана организация по дефолту, то ставим по ультрадефолту other
            logger.error(f'[{self.conn_type}] В конфиге не указана организация и коннектор не смог определить её! '
                         f'Выставляю other')
            org = 'other'
        return org

    @staticmethod
    def cast(event: dict):
        """приведение типов"""
        for k, v in event.items():
            if isinstance(v, datetime):
                event[k] = event[k].isoformat()
            if isinstance(v, decimal.Decimal):
                event[k] = int(event[k])
            if isinstance(v, ObjectId):
                event[k] = str(event[k])
            try:
                event[k] = int(event[k])
            except (ValueError, TypeError):
                pass
            if k in ['username']:
                event[k] = str(event[k])

        return event

    def basically_transformation(self, event):
        """
            Привести поля к стандартному виду через конфиги
        """

        def determine_common_type(event):
            """Определить основной тип событий. http, network, file, email etc"""

            def validate(regex, field):
                if not regex:
                    return False
                if not field:
                    return False
                cwr = re.compile(regex)
                try:
                    res = cwr.match(field)
                except Exception as err:
                    raise DetermineException(f'[{self.conn_type}] Ошибка {err} в обработке регулярки. '
                                             f'Регулярка: {regex}, строка: {field}, событие целиком: {event}')
                return res

            determine_common_type = setting['sensors'][self.conn_type]['determine_common_type']
            for common_types, type_conditions in determine_common_type.items():
                for field_name, regex_str in type_conditions.items():
                    res = validate(regex_str, event.get(field_name))
                    if res:
                        return common_types
            return 'file'

        def get_transform_rule(event):
            """Получить актуальное правило, по которому будет рисоваться событие"""
            transform_rules = setting['sensors'][self.conn_type].get('transform_rules')
            if not transform_rules:
                raise TransformationException(f'[{self.conn_type}] Конфиг не содержит transform_rules')
            etype = event.get('event_type')
            ctype = event.get('common_type')

            if not ctype:
                # Есои не сгенерировали
                ctype = determine_common_type(event)

            try:
                cwr = transform_rules[etype][ctype]  # current working rule
            except KeyError:
                raise TransformationException(
                    f'[{self.conn_type}] Не удалось найти правило для обработки {etype}->{ctype}. Событие: {event}')
            except Exception as err:
                raise TransformationException(
                    f'[{self.conn_type}] Случилось что-то страшное... {etype}->{ctype}. ERROR: {err} Событие: {event}')
            return cwr, ctype

        def regex_find(regex, field):
            if not field or not regex:
                return False
            cwr = re.compile(regex)
            try:
                cwr.findall(field)
            except Exception as err:
                logger.critical(f'[{self.conn_type}] Ошибка {err} в обработке регулярки. '
                                f'Регулярка: {regex}, строка: {field}, событие целиком: {event}')
                return field
            return cwr.findall(field)

        def normalize_ip(ip):
            """ Приведение ip к единому виду"""

            def hex2ip(hex_ip):
                """ 0xXXXXXXXX -> ip """
                hex_data = hex_ip[2:]
                if len(hex_data) < 8:
                    hex_data = ''.join(('0', hex_data))
                ipaddr = "%i.%i.%i.%i" % (
                    int(hex_data[0:2], 16), int(hex_data[2:4], 16), int(hex_data[4:6], 16), int(hex_data[6:8], 16))
                return ipaddr

            def int2ip(int_ip):
                if int_ip < 0:  # иногда в базах встречаются отрицательные значения
                    normal_int_ip = ip * -1
                else:
                    normal_int_ip = int_ip
                return str(ipaddress.IPv4Address(normal_int_ip))

            if not ip:
                return None

            if isinstance(ip, int):
                return int2ip(ip)

            if isinstance(ip, bytes):
                bytes_ip = int.from_bytes(ip, byteorder='big')
                return int2ip(bytes_ip)

            if '0x' in ip:
                return hex2ip(ip)
            else:
                logger.error(f'[{self.conn_type}] Не удалось конвертировать {ip} в ip адрес')
                return None

        event = self.cast(event)
        trans_rule, common_type = get_transform_rule(event)

        norm_event = {'common_type': common_type}  # Нормализованное событие

        for k, v in trans_rule.items():
            custom_type, expression = v.split('-->')
            if custom_type == 'bool':
                if not expression:
                    norm_event.update({k: None})
                else:
                    norm_event.update({k: bool(int(expression))})

            if custom_type == 'int':
                norm_event.update({k: int(expression)})
            if custom_type == 'str':
                norm_event.update({k: str(expression)})
            if custom_type == 'key':
                norm_event.update({k: event[expression]})
            if custom_type == 'regex':
                field_key, regex = expression.split("<--'")
                regex = regex[:-1]
                res = regex_find(regex, event.get(field_key))
                if not res:
                    norm_event.update({k: None})
                elif len(res) == 1:
                    norm_event.update({k: res[0]})
                else:
                    if isinstance(event.get(field_key), str):
                        norm_event.update({k: event.get(field_key)})
                    else:
                        norm_event.update({k: None})
                    logger.warning(f'[{self.conn_type}] Неожиданный результат от регулярки {res} regex=[{regex}] '
                                   f'field_key=[{event.get(field_key)}]')
            if custom_type == 'int2ip':
                try:
                    norm_event.update({k: normalize_ip(event[expression])})
                except ipaddress.AddressValueError:
                    logger.warning(
                        f'[{self.conn_type}] Не удалось конвертировать int поле в ip адрес: {event[expression]}')
                    norm_event.update({k: None})
                except Exception as err:
                    logger.warning(f'[{self.conn_type}] Не удалось конвертировать {event[expression]} поле в ip адрес:')
                    logger.exception(err)
                    norm_event.update({k: None})

        return norm_event

    def transformation(self, event):
        """Привести поля к стандартному виду"""
        norm_event = {}
        pre_transformer = PreTransformer()

        def add_require(e):
            e.update({'segment': self.environment.get('segment')})
            e.update({'av': setting['sensors'][self.conn_type]['device']})
            e.update({'env_alias': self.env_alias})
            e.update({'organization': self.define_organisation(e)})
            return e

        # if not setting['sensors'][self.conn_type].get('determine_common_type'):
        #     # сли в конфиге нет описания типов событий - запускаем маппинг и дальнейшую трансформацию для СИЕМа
        #     event.update({'av': setting['sensors'][self.conn_type]['device']})  # for pre_transformer
        #     event = pre_transformer.pre_transform_event(event)
        event.update({'av': setting['sensors'][self.conn_type]['device']})  # for pre_transformer
        event = pre_transformer.pre_transform_event(event)
        if "transform_rules" in setting['sensors'][self.conn_type]:
            norm_event = self.basically_transformation(event)
        else:
            norm_event = event

        norm_event = add_require(norm_event)
        return norm_event

    def is_identical_events(self, event, full_events_list):
        """
         Проверяем, не было ли раньше такого события
        :param event:
        :param full_events_list:
        :return:
        """

        def get_search_dict(event, abort_rules):
            """Сформировать два словаря для поиска в монге событий, которые задублированы"""
            include_identical_keys = abort_rules.get('include_identical_keys')
            exclude_identical_keys = abort_rules.get('exclude_identical_keys')
            search_dict_includes = {}
            search_dict_excludes = dict(event)

            if isinstance(exclude_identical_keys, list):
                for key in exclude_identical_keys:
                    search_dict_excludes.pop(key)

            if isinstance(include_identical_keys, list):
                for key in include_identical_keys:
                    search_dict_includes.update({key: event.get(key)})

            return search_dict_includes, search_dict_excludes

        def abort_identical_db(event):
            """
            Не записывать в базу, если это повтор
             Поиск по базе
            :param event:
            :return:
            """
            abort_rules = setting['sensors'][self.conn_type]['abort_rules']
            if not abort_rules:
                return False
            search_dict1, search_dict2 = get_search_dict(event, abort_rules)
            # проверка по коллекции, в которую собрались писать
            # organization = self.define_organisation(event)
            if event.get('organization'):
                organization = event.get('organization')
            else:
                organization = self.environment['organization']

            collection = self.mongo[f'unicon_{self.conn_type}'][organization]
            if search_dict1 and len(list(collection.find(search_dict1))) == 0:
                return False
            elif search_dict2 and len(list(collection.find(search_dict2))) == 0:
                return False
            return True

        def abort_identical_local(new_event, events_list):
            """
            Не записывать в базу, если это повтор
             Поиск повторов в словаре, до записи в базу
            :param new_event:
            :param events_list:
            :return:
            """
            identical = False
            abort_rules = setting['sensors'][self.conn_type]['abort_rules']
            normal_new_event = get_search_dict(new_event, abort_rules)
            for event in events_list:
                if get_search_dict(event, abort_rules) == normal_new_event:
                    return True

            return identical

        if not abort_identical_local(event, full_events_list):
            if not abort_identical_db(event):
                return False
            else:
                logger.debug(f"[{self.conn_type}] --Event already exist in db [{event.get('event_id')}]: {event}")
                return True
        else:
            logger.debug(f"[{self.conn_type}] "
                         f"-Event already exist in local temp full_events_list [{event.get('event_id')}]: {event}")
            return True
        return True

    def insert2mongo(self, event_list):
        """
        Преобразуем список всех событий в словарь списков событий по каждой организации.
        Записываем события по каждой организации в свой collection
        :param event_list:
        :return:
        """

        def make_event_dict():
            """
            Собираем словарь списоков:
                key - organization
                value - event_list
            """
            tmp_event_dict = {}
            for event in event_list:
                if 'event_type' in event and event['event_type'] and self.filters['exclude_types'] \
                        and event['event_type'] in self.filters['exclude_types']:
                    logger.debug(f"[{self.conn_type}] По {event['event_type']} реагирование временно не ведётся, "
                                 f"событие в базу заноситься не будет {event}")
                else:
                    # organization = self.define_organisation(event)
                    # event.update({'organization': organization})
                    if event.get('organization'):
                        organization = event.get('organization')
                    else:
                        organization = self.environment['organization']

                    # Добавим время и статус. Статус 0, значит событие еще не отправлялось в бота.
                    event.update({'_receive_dt': datetime.utcnow()})
                    event.update({'_status': 0})
                    if organization in tmp_event_dict:
                        tmp_event_list = tmp_event_dict[organization]
                        tmp_event_list.append(event)
                        tmp_event_dict.update({organization: tmp_event_list})
                    else:
                        tmp_event_list = [event]
                        tmp_event_dict.update({organization: tmp_event_list})
                    logger.debug(f"[{self.conn_type}] В базу записано новое событие [{event.get('event_id')}]: {event}")
            return tmp_event_dict

        if event_list:
            event_dict = make_event_dict()
            if event_dict:
                for key in event_dict:
                    collection = self.mongo[f'unicon_{self.conn_type}'][key]
                    collection.insert_many(event_dict[key])

    def collect_events(self, last_position=False, event_id=False):
        """ Забираем события из базы АВ"""
        full_events_list = []

        for e in self.select_events(last_position=last_position, event_id=event_id):
            try:
                ce = self.transformation(e)
            except TransformationException as err:
                logger.error(err)
                continue
            if not ce:
                logger.error(f"Не удалось разобрать событие {e.get('event_id')}: {e}")
                continue
            if not event_id:
                if not self.is_identical_events(ce, full_events_list):
                    full_events_list.append(ce)
            else:
                full_events_list.append(ce)
        self.insert2mongo(full_events_list)


class Processor:
    def __init__(self, device, send_setting):
        self.__sender_settings = send_setting
        self.__sender_client = self.get_sender_client()
        self.device = device

    @staticmethod
    def delete_service_fields(_event):
        """
        Удаление из события служебных полей, начинающихся с "_"
        :return:
        """
        empty_keys = [k for k, v in _event.items() if k[0] == "_"]
        for k in empty_keys:
            del _event[k]
        return _event

    def get_sender_client(self):
        """
        Инициализация нужного клиента в зависимости от метода отправки событий в бота
        :return:
        """
        if self.__sender_settings['method'] == 'messila_api':
            from modules.messila_api import MessilaApiClient
            logging.debug('loading messila_api_client')
            messila_api_client = MessilaApiClient(api_url=self.__sender_settings['credentials']['messila_api']['host'],
                                                  login=self.__sender_settings['credentials']['messila_api']['login'],
                                                  password=self.__sender_settings['credentials']['messila_api'][
                                                      'password'],
                                                  verify=self.__sender_settings['credentials']['messila_api']['verify'])
            logging.debug('Messila_api_client loaded')
            return messila_api_client

        if self.__sender_settings['method'] == 'kafka':
            from modules.kafka_con import Producer
            logging.debug('loading producer')
            producer = Producer(auth=self.__sender_settings['credentials']['kafka']['auth_type'],
                                servers=self.__sender_settings['credentials']['kafka']['servers'],
                                **self.__sender_settings['credentials']['kafka']['auth_params'])
            logging.debug('Producer loaded')
            return producer

        if self.__sender_settings['method'] == 'nxlog':
            from socutils import NXLogSender
            logging.debug('loading NxlogSender')
            nxlog = NXLogSender(self.__sender_settings['credentials']['nxlog']['host'],
                                self.__sender_settings['credentials']['nxlog']['port'])
            nxlog.connect()
            logging.debug('NxlogSender loaded')
            return nxlog

        return False

    def sender_close(self):
        """ Если необходимо закрывать за собой сессии """
        if self.__sender_settings['method'] == 'nxlog':
            self.__sender_client.close()

    def send2bot(self, event):
        """
        Определение метода отправки
        :param event:
        :return:
        """
        if self.__sender_settings['method'] == 'messila_api':
            return self.__send2messila_api(event)
        if self.__sender_settings['method'] == 'kafka':
            return self.__send2kafka(event)
        if self.__sender_settings['method'] == 'nxlog':
            return self.__send2nxlog(event)

        logger.error(f'[{self.device}] В конфиге не определён метод отправки событий в бота!')
        return False

    def __send2nxlog(self, event):
        """
        Отправка события в nxlog
        :param event:
        :return:
        """
        post_transformer = PostTransformer()

        def nxlog_formater(event, devtype):
            """ Форматируем событие для nxlog'a """

            def md5_from_raw(raw):
                import hashlib
                hash_t = hashlib.md5()
                hash_t.update(str(raw).encode('utf8'))
                return hash_t.hexdigest()

            def transform_time(_time: str):
                def pars_event_time(t: str):
                    try:
                        _event_time = parse(t)
                    except Exception as err:
                        logger.error(err)
                        return None
                    return _event_time

                event_time = pars_event_time(_time)
                if not event_time:
                    return _time
                try:
                    _new_time = tz.localize(event_time)
                except Exception as err:
                    if err.args[0] == "Not naive datetime (tzinfo is already set)":
                        return str(event_time)
                    return str(event_time)
                new_time = _new_time.isoformat()
                return new_time

            try:
                event["EventTime"] = transform_time(event["EventTime"])
                event["DetectionTime"] = transform_time(event["DetectionTime"])
                new_event = {
                    "EventTime": event["EventTime"],
                    "DetectionTime": event["DetectionTime"],
                    "Hostname": socket.gethostname(),
                    "SeverityValue": self.__sender_settings['credentials']['nxlog']['nxlog_attributes'].get(
                        'SeverityValue'),
                    "Severity": self.__sender_settings['credentials']['nxlog']['nxlog_attributes'].get('Severity'),
                    "Organization": event['Organization'],
                    "OrgID": self.__sender_settings['credentials']['nxlog']['nxlog_attributes'].get('OrgID'),
                    "DevCat": self.__sender_settings['credentials']['nxlog']['nxlog_attributes'].get('DevCat'),
                    "DevSubCat": self.__sender_settings['credentials']['nxlog']['nxlog_attributes'].get('DevSubCat'),
                    "DevType": devtype,
                    "DevVendor": self.__sender_settings['credentials']['nxlog']['nxlog_attributes'].get('DevVendor'),
                    "raw": event,
                    "md5": md5_from_raw(event)

                }
            except Exception as err:
                logger.error(f'Не удается отформатировать событие. error {err}')
                return False
            return new_event

        siem_event = post_transformer.post_transform_event(event)
        if not isinstance(self.__sender_settings['credentials']['nxlog']['nxlog_attributes'].get('DevType'), list):
            event = nxlog_formater(siem_event,
                                   self.__sender_settings['credentials']['nxlog']['nxlog_attributes'].get('DevType'))
            if not event:
                return False
            return self.__sender_client.send_event(message=event)

        if isinstance(self.__sender_settings['credentials']['nxlog']['nxlog_attributes'].get('DevType'), list):
            res = False
            for devtype in self.__sender_settings['credentials']['nxlog']['nxlog_attributes'].get('DevType'):
                event = nxlog_formater(siem_event, devtype)
                if not event:
                    return False
                res = self.__sender_client.send_event(message=event)
            return res

    def __send2kafka(self, event):
        """
        отправка события в kafka
        :param event:
        :return:
        """
        event = self.delete_service_fields(event)
        self.__sender_client.send(topic=self.__sender_settings['credentials']['kafka']['siem_topic'], data=event)
        return True

    def __send2messila_api(self, event):
        """
        Отправка события в Messila API
        :param event: 
        :return: 
        """

        def clear_none(_event):
            """ даление ключей с None'выми значениями """
            empty_keys = [k for k, v in _event.items() if v is None]
            for k in empty_keys:
                del _event[k]
            return _event

        event = clear_none(event)
        event = self.delete_service_fields(event)
        if event.get('event_id'):
            if isinstance(event['event_id'], int):
                event.update({"event_id": str(event['event_id'])})
        return self.__sender_client.send_event(event)


class WorkTime:
    """
    Управленияе временем
    """

    def __init__(self):
        self.mongo = pymongo.MongoClient(host=mongo_host, port=mongo_port)

    def get_last_position(self, device):
        """
        Получаем дату, с которой нужно собрать новые сработки
        Так как собирать будем с какой-то даты до настоящего момента, 
            то в следующий раз нужно будет собирать данные со времени сейчас 
        :param device: база в которой нужно брать время
        :return: 
            ldt - last date 
            new_lp_id - id нового last_position в монге 
        """
        last_dt = None
        new_lp_id = None

        collection = self.mongo[f'unicon_{device}']['work_time']
        try:
            lp = collection.find({"status": 1}).sort('_id', -1).limit(1)[:1][0]
            last_dt = lp.get('last_position')
            logger.info(f'[{device}] Last position {last_dt}')
            last_dt = datetime.strptime(last_dt, '%Y-%m-%d %H:%M:%S') - timedelta(
                hours=setting['time_indent'])  # str -> datetime; -N hour
            last_dt = last_dt.strftime('%Y-%m-%d %H:%M:%S')
            logger.info(f'[{device}] Собираем с даты {last_dt}')
            new_lp_id = collection.insert_one(
                {"status": 0, 'last_position': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}).inserted_id
            logger.info(f'[{device}] Новая дата {new_lp_id}')
        except IndexError:
            logger.info("Похоже это первый запуск, так как коллекция work_time чиста")
        except Exception as err:
            logger.error(err)

        if not last_dt:
            last_dt = datetime.now() - timedelta(hours=setting['stat_range'])
            last_dt = last_dt.strftime('%Y-%m-%d %H:%M:%S')
            new_lp_id = collection.insert_one({"status": 0, 'last_position': last_dt}).inserted_id
            logger.warning(
                f"[{device}] Не найдено время начала последнего сбора событий. "
                f"Зададим по дефолту (-{setting['stat_range']}h)")
        if device == "drweb":
            last_dt = datetime.strptime(last_dt, '%Y-%m-%d %H:%M:%S').strftime("%Y%m%d%H%M%S%f")[:-3]
        return last_dt, new_lp_id

    def update_last_position(self, device, new_lp_id):
        """

        Если сбор данных к нам в базу прошёл успено,
        то разрешаем новый last_position к использованию при следующем включении
        :param device: база в которой нужно брать время
        :param new_lp_id: id нового LP, который нужно пометить как подтверждённый
        :return:
        """
        collection = self.mongo[f'unicon_{device}']['work_time']
        collection.update_one({'_id': new_lp_id}, {"$set": {"status": 1}})
        logger.info(f'[{device}] Новая дата начала последнего сбора событий {new_lp_id} подтверждена')


class StartTime:
    """
    Управленияе временем v2 для планировщика
    """

    def __init__(self):
        self.mongo = pymongo.MongoClient(host=mongo_host, port=mongo_port)

    def get_last_start(self, device):
        """
        Получаем время когда в прошлый раз запустили сборщик
        :param device: база в которой нужно брать время
        :return: 
        """
        last_start_dt = None
        new_ls_id = None

        collection = self.mongo[f'unicon_{device}']['start_time']
        try:
            ls = collection.find({"status": 1}).sort('_id', -1).limit(1)[:1][0]  # последний успершный старт
            # last_start_dt = ls.get("last_start_dt")
            last_start_dt = datetime.strptime(ls.get("last_start_dt"), '%Y-%m-%d %H:%M:%S')
            # logger.info('Last start connector for {} on {}'.format(device, last_start_dt))
        except pymongo.errors.ServerSelectionTimeoutError:
            logger.critical('MongoDB не запущена, или у неё проблемы')
            sys.exit(1)
        except IndexError as err:
            logger.warning(err)

        if not last_start_dt:
            # при первом запуске нет предыдущей даты, так что создаём её сами
            last_start_dt = datetime.now()
            last_start_dt = last_start_dt.strftime('%Y-%m-%d %H:%M:%S')
            collection.insert_one({"status": 1, 'last_start_dt': last_start_dt})
            last_start_dt = datetime.strptime(last_start_dt, '%Y-%m-%d %H:%M:%S')
            logger.warning(f'[{device}] Сбор данных по этому сенсору ранее не происходил. '
                           f'Сейчас первый запуск {last_start_dt}')

        return last_start_dt

    def create_new_last_start(self, device):
        collection = self.mongo[f'unicon_{device}']['start_time']
        new_last_start_dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        new_ls_id = collection.insert_one(
            {"status": 0, 'last_start_dt': new_last_start_dt}
        ).inserted_id
        logger.info(f'[{device}] Новая дата последнего старта {new_last_start_dt} {new_ls_id}')
        return new_ls_id

    def confirm_new_last_start(self, device, new_ls_id):
        """

        Если сбор данных к нам в базу прошёл успено, 
        то разрешаем новый last_start к использованию при следующем включении
        :param device: база в которой нужно брать время
        :param new_ls_id: id нового LS, который нужно пометить как подтверждённый 
        :return: 
        """
        collection = self.mongo[f'unicon_{device}']['start_time']
        collection.update_one({'_id': new_ls_id},
                              {"$set": {"status": 1, "last_end_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}})
        logger.info(f'[{device}] Новая дата последнего старта {new_ls_id} подтверждена')


def collect(device, last_position=None, event_id=None, env=None):
    """ Сборщик событий """
    if last_position:
        try:
            environments = setting['sensors'][device]['environments']
        except KeyError:
            logger.error(f'Для сенсора {device} нет соответствующего конфига')
            sys.exit(1)

        for _env, params in environments.items():
            logger.info('Search in environments [{}]'.format(_env))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    telnet = s.connect_ex((environments[_env]['external_db']['server'],
                                           environments[_env]['external_db']['port']))
                except Exception as err:
                    logger.error(f"[{device}] Проблемы с доступом к серверу БД "
                                 f"{environments[_env]['external_db']['server']}: {err}")
                    return False
            if telnet:
                logger.error(f"[{device}] Нет доступа до сервера {environments[_env]['external_db']['server']}")
                return False
            iv = Collector(conn_type=device, environment=environments[_env], env_alias=_env)
            try:
                iv.collect_events(last_position=last_position)
            except Exception as err:
                logger.exception(err)
                logger.error(f"[{device}] Проблемы со сбором данных с БД {environments[_env]['external_db']['server']} "
                             f"под УЗ {environments[_env]['external_db']['user']}")
                return False
            return True

    elif event_id and env:
        environments = setting['sensors'][device]['environments']
        logger.info(f'[{device}] Search in environments [{env}]')
        iv = Collector(conn_type=device, environment=environments[env], env_alias=env)
        iv.collect_events(event_id=event_id)
        return True


def process(device):
    """ Отправлятор событий """

    def get_collections_list(db_name):
        """ Получаем список коллекций из базы """
        collections_list = []
        db = mongo[f'unicon_{db_name}']
        for _collection in db.list_collection_names():
            if 'system.' not in _collection:
                collections_list.append(_collection)
        return collections_list

    def delete_old_events(_collection):
        storage_time = 14
        if setting.get('storage_time'):
            storage_time = setting.get('storage_time')

        res = _collection.delete_many(
            {
                "_status": 1,
                "_receive_dt": {
                    "$lt": datetime.utcnow() - timedelta(days=storage_time)
                }
            })
        if res.raw_result.get('n'):
            logger.info(f"Из хранилища удалено {res.raw_result.get('n')} событий старше {storage_time} дней")

    proc = Processor(device, setting['sensors'][device]['send2bot'])
    mongo = pymongo.MongoClient(host=mongo_host, port=mongo_port)
    collections_list = get_collections_list(device)
    for collection_name in collections_list:
        if collection_name in ['start_time', 'work_time']:
            continue
        logger.debug(f'[{device}] Поиск новых событий в коллекции {collection_name}')
        collection = mongo[f'unicon_{device}'][collection_name]
        new_events = collection.find({'_status': 0})
        if new_events.count() == 0:
            logger.debug(f'[{device}] Новые события для отправки в брокер не найдены')
        sending_events = 0
        len_events = new_events.count()
        for event in new_events:
            Collector.cast(event)
            event_id = event['_id']

            if proc.send2bot(event):
                sending_events = sending_events + 1
                collection.update_one({'_id': ObjectId(event_id)}, {"$set": {"_status": 1}})
                logger.debug(f'[{device}] Статус события {event_id} изменен')
        logger.debug(f'[{device}] Sending {sending_events}/{len_events} events to bot')
        delete_old_events(collection)
    proc.sender_close()
