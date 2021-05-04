from socutils import get_settings, exceptions
import logging
import sys
import os

logger = logging.getLogger("configer")


def read_setting(path):
    try:
        config = get_settings(path)
    except exceptions.SettingsFileNotExistError:
        logger.error(f'{path} Not found')
        sys.exit(1)
    return config


class PrivacyManager:
    def __init__(self, cpath='/appconfig', public_config_name="setting", privacy_config_name="secret"):
        self.public_config = read_setting(f'{cpath}/{public_config_name}.yaml')
        self.__privacy_data = read_setting(f'{cpath}/secure/{privacy_config_name}.yaml')

    def __get_secret(self, key_path):
        """ получаем приватные данные из секьюрного конфига"""
        if key_path not in self.__privacy_data:
            logger.critical(f'Not fount {key_path} in privacy_config')
            return False
        # print(f'{path} - > {privacy_data.get(path)}')
        return self.__privacy_data.get(key_path)

    def __get_recursively(self, search_dict, field, d_path=None):
        """ Получаем список объектов, которые нужно заменить """
        paths_to_fields = []

        for key, value in search_dict.items():

            if value == field:
                if not d_path:
                    paths_to_fields.append(key)
                if d_path:
                    paths_to_fields.append(d_path + '.' + key)

            elif isinstance(value, dict):
                if d_path:
                    key = d_path + '.' + key
                results = self.__get_recursively(value, field, key)
                for result in results:
                    paths_to_fields.append(result)

        return paths_to_fields

    def get_production_config(self):
        """ Подставляем приватные данные в публичный конфиг """
        from copy import deepcopy
        prod_setting = deepcopy(self.public_config)

        def set_val(path='', new_val=None):
            """ Вставляем значение в словарь по пути ключей """
            if '.' in path:
                chunks = path.split('.')
                chunks.reverse()
                val = prod_setting

                while len(chunks) > 1:
                    chunk = chunks.pop()
                    if chunk.isdigit():
                        val = val[int(chunk)]
                    else:
                        val = val[chunk]

                if chunks[0].isdigit():
                    val[int(chunks[0])] = new_val
                else:
                    val[chunks[0]] = new_val

                return True

            try:
                prod_setting[path] = new_val
                return True
            except (KeyError, IndexError):
                return False

        paths = self.__get_recursively(prod_setting, '<privacy>')
        for path in paths:
            secret = self.__get_secret(path)
            set_val(path=path, new_val=secret)
        return prod_setting


def configer():
    global_env = os.environ.get('GLOBAL_ENV')
    logger.debug(f'Global environment {global_env}')
    if not global_env:
        if os.path.exists('/opt/unicon/data'):
            logger.debug('Get settings from sdata')
            cpath = '/opt/unicon/data'
        else:
            logger.debug('Get settings from appconfing')
            cpath = '/opt/localconfigs/unicon/appconfig'
    elif global_env == 'docker':
        cpath = '/appconfig'
    else:
        print('ERRRO::Unknown Environment')
        sys.exit(1)
    config = read_setting(f'{cpath}/unicon-setting.yaml')

    def _get_cfg_list():
        """ Получаем список конфигов сенсоров
            FIY: это не лишние действия, это понадобится, когда переделаю на многопоточность
        """
        config.update({'sensors': {}})
        conf_files = filter(lambda x: x.endswith('.yaml') and not x.startswith('unicon-setting'),
                            os.listdir(path=f"{cpath}"))
        cfg_list = list(map(lambda line: line.split('.')[0], conf_files))
        return cfg_list

    _sensors = _get_cfg_list()

    if len(_sensors) == 0:
        logger.error('Нет ни единого конфига АВ!')

    for conf_sensor in _sensors:
        pm = PrivacyManager(cpath=cpath, public_config_name=conf_sensor, privacy_config_name=conf_sensor)
        config['sensors'].update({**config['sensors'], **pm.get_production_config()})
    return config
