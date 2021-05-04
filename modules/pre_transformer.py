import logging
import re

logger = logging.getLogger('pre_transformer')


class PreTransformer:
    """ Используется для определения типов событий и их обогащения, если в конфиге нет раздела determine_common_type"""

    def __init__(self):
        pass

    def pre_transform_event(self, event):
        if 'av' not in event:
            logger.warning('Не смогли определить тип события, не знаем что за av')
            return event
        if event.get('av') == 'kaspersky':
            p = Kaspersky()
            return p.pre_transform_event(event)
        if event.get('av') == 'symantec':
            p = Symantec()
            return p.pre_transform_event(event)
        if event.get('av') == 'wdefender':
            p = Defender()
            return p.pre_transform_event(event)
        if event.get('av') == 'drweb':
            return event


class Kaspersky:
    def __init__(self):
        self.cwe = {}

    @staticmethod
    def __determine_common_type(event):
        """ определяем тип события """

        if event.get('task_display_name') in ['Веб-Антивирус'] and event.get('par8') in ['0', '70']:
            return 'http_reputation'

        if (event.get('task_display_name') in ['Защита от веб-угроз']) or \
                (event.get('task_display_name') in ['Веб-Антивирус'] and event.get('par8') not in ['0', '70']):
            return 'http_malware'

        if event.get('task_display_name') in ['Защита от почтовых угроз', 'Почтовый Антивирус'] \
                and event.get('par8') != 0 \
                and event.get('par2') \
                and event['par2'].find('From:'):
            return 'email_malware_from'

        if event.get('task_display_name') in ['Защита от почтовых угроз', 'Почтовый Антивирус'] \
                and event.get('par8') != 0 \
                and event.get('par2') \
                and event['par2'].find('To:'):
            return 'email_malware_to'

        if event.get('task_display_name') in ['Защита от почтовых угроз', 'Почтовый Антивирус'] \
                and event.get('par8') == 0 \
                and event.get('par2') \
                and event['par2'].find('From:'):
            return 'email_policy_from'

        if event.get('task_display_name') in ['Защита от почтовых угроз', 'Почтовый Антивирус'] \
                and event.get('par8') == 0 \
                and event.get('par2') \
                and event['par2'].find('To:'):
            return 'email_policy_to'

        if event.get('task_display_name') in ['Защита от сетевых угроз', 'Защита от сетевых атак']:
            return 'network'

        if event.get('par2') and re.compile(r"^[A-Za-z]\:\\.+?$").match(event.get('par2')):
            return 'file'

        if event.get('event_type') == "0000012f":
            return 'file2'

        if event.get('par2') and re.compile(r"\\\\(.*)").match(event.get('par2')):
            return 'file3'

        if event.get('par2') and re.compile(r"^(HKLM\\|HKCU\\|HKU\\|HKCR\\|HKCC\\).+?$").match(event.get('par2')):
            return 'registry'

        if event.get('par2') == "System Memory":
            return 'memory_obj'
        if event.get('event_type') in ['000000d6', '000000d3', 'security']:
            return 'rtp_disable'
        return 'NEW'

    def __enrichment_data(self):
        """ Обогащение сырого события данными """
        '''block'''
        if ((self.cwe.get('event_type') == 'GNRL_EV_OBJECT_DELETED'
             and self.cwe.get('event_type_display_name') == 'Объект удален')
                or (self.cwe.get('event_type') == 'GNRL_EV_OBJECT_DELETED'
                    and self.cwe.get('task_display_name') == 'Защита от почтовых угроз'
                    and self.cwe.get('par8') == 0)
                or (self.cwe.get('event_type') == 'GNRL_EV_OBJECT_BLOCKED')
                or (self.cwe.get('event_type') == 'GNRL_EV_ATTACK_DETECTED')
                or (self.cwe.get('event_type') == 'GNRL_EV_VIRUS_FOUND')
                or (self.cwe.get('event_type') == 'GNRL_EV_OBJECT_QUARANTINED')):
            self.cwe.update(block=True)
        else:
            self.cwe.update(block=False)

        '''delete'''
        if ((self.cwe.get('event_type') == 'GNRL_EV_OBJECT_DELETED'
             and self.cwe.get('event_type_display_name') == 'Объект удален')
                or (self.cwe.get('event_type') == 'GNRL_EV_OBJECT_QUARANTINED')
                or (self.cwe.get('event_type') == 'GNRL_EV_OBJECT_DELETED' and self.cwe.get(
                    'task_display_name') == 'Защита от почтовых угроз' and self.cwe.get('par8') == 0)):
            self.cwe.update(deleted=True)
        else:
            self.cwe.update(deleted=False)

    def __update_data(self, event):
        if self.cwe.get('common_type') == 'http_reputation':
            if 'des' in event and event['des'].find('(проверка по базе фишинговых веб-адресов)') > 0:
                self.cwe.update(par5='Phishing')

    def pre_transform_event(self, event: dict):
        self.cwe = event
        common_type = self.__determine_common_type(event)
        self.cwe.update(common_type=common_type)
        self.__enrichment_data()
        self.__update_data(event)
        return {**event, **self.cwe}


class Symantec:
    def __init__(self):
        self.cwe = {}

    @staticmethod
    def __determine_common_type(event):
        """ определяем тип события """
        if event.get('event_type') in ['NETWORK', 'network']:
            return 'network'
        if event.get('event_type') in ['MALWARE', 'malware']:
            return 'file'
        if event.get('event_type') in ['DISABLE_PROTECTION']:
            return 'rtp_disable'

    def __enrichment_data(self):
        """ Обогащение сырого события данными """
        '''delete'''
        if self.cwe.get('action') and self.cwe.get('deleted') == 0 and (
                self.cwe.get('action').lower() == 'deleted' or
                self.cwe.get('action').lower() == 'cleaned by deletion' or
                self.cwe.get('action').lower() == 'cleaned' or
                self.cwe.get('action').lower() == 'quarantined'
        ):
            self.cwe.update(deleted=True)
        else:
            self.cwe.update(deleted=False)

    def pre_transform_event(self, event: dict):
        self.cwe = event
        common_type = self.__determine_common_type(event)
        self.cwe.update(common_type=common_type)
        self.__enrichment_data()
        return {**event, **self.cwe}


class Defender:
    def __init__(self):
        self.cwe = {}

    @staticmethod
    def __determine_common_type(event):
        """ определяем тип события """
        if event.get('common_type'):
            return event.get('common_type')
        return 'unknown'

    def __enrichment_data(self):
        """ Обогащение сырого события данными """
        '''deleted'''
        if self.cwe.get('action') \
                and self.cwe.get('action').lower() == 'remove' \
                and self.cwe.get('action_success').lower() == 'success':
            self.cwe.update(deleted=True)
        else:
            self.cwe.update(deleted=False)

        '''block'''
        if self.cwe.get('action') and (
                self.cwe.get('action').lower() == 'remove' or
                self.cwe.get('action').lower() == 'clean' or
                self.cwe.get('action').lower() == 'quarantine'
        ) and self.cwe.get('action_success').lower() == 'success':
            self.cwe.update(block=True)
        else:
            self.cwe.update(block=False)

    def pre_transform_event(self, event: dict):
        self.cwe = event
        common_type = self.__determine_common_type(event)
        self.cwe.update(common_type=common_type)
        self.__enrichment_data()
        return {**event, **self.cwe}
