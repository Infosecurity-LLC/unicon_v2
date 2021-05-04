import logging
import re
from datetime import datetime
from ipaddress import ip_address

logger = logging.getLogger('post_transformer')


class PostTransformer:
    """ Финальная трансформация перед отправкой в SIEM"""

    def __init__(self):
        pass

    def post_transform_event(self, event):
        if 'av' not in event:
            logger.error('Не смогли определить тип события, не знаем что за av')
            return False
        if event.get('av') == 'kaspersky':
            p = Kaspersky()
            return p.post_transform_event(event)
        if event.get('av') == 'symantec':
            p = Symantec()
            return p.post_transform_event(event)
        if event.get('av') == 'eset':
            p = Eset()
            return p.post_transform_event(event)
        if event.get('av') == 'wdefender':
            p = Defender()
            return p.post_transform_event(event)
        if event.get('av') == 'drweb':
            p = Drweb()
            return p.post_transform_event(event)


class Drweb:
    def __init__(self):
        self.for_siem = {}

    def __formater(self, event):
        self.transform(event)

    def __get_ips(self):
        return

    def transform(self, event):
        self.for_siem.update({**{
            "Organization": event.get('organization'),
            "EventTime": datetime.strptime(str(event.get("recievedtime")), "%Y%m%d%H%M%S%f").isoformat(),
            "DetectionTime": datetime.strptime(str(event.get("recievedtime")), "%Y%m%d%H%M%S%f").isoformat(),
        }, **event})

    def post_transform_event(self, event):
        self.for_siem = {}
        self.__formater(event)
        return self.for_siem


class Defender:
    def __init__(self):
        self.for_siem = {}

    def __formater(self, event):
        if event.get('common_type') in ['file',
                                        'containerfile',
                                        'regkeyvalue',
                                        'process',
                                        'behavior']:
            self.file(event)
        if event.get('common_type') in ['system']:
            self.rtp_disable(event)

    def __get_ips(self, defender_ip):
        ips = defender_ip.split(', ')
        result = {}
        for ip in ips:
            try:
                addr = ip_address(ip)
            except ValueError:
                continue
            result[f'ipv{addr.version}'] = ip
        return result

    def file(self, event):
        self.for_siem.update({
            "EventName": f'def_{event.get("common_type")}',
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "EventTime": event.get("action_time"),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "SensorName": f'av_{event.get("av")}',
            "ModuleName": "Файловый Антивирус",
            "Block": event.get("block"),
            "Action": event.get("action"),
            "ActionSuccess": event.get("action_success"),
            "ObjectType": "MalwareObject",
            "ObjectPath": event.get("object_path"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "Severity_desc": event.get("severity_desc"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            # "Sha256": event.get("object_sha256"),
            # "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            # "HostDomain": event.get("comp_dom"),
            # "IP": event.get("comp_ip"),
            "Mask": event.get("comp_net_mask"),
            "MAC": event.get("comp_mac"),
            "TypeActivity": "Other",
            "UserName": event.get('user_name'),
            "ProcessName": event.get('process'),
            "ScanType": event.get('scan_type'),
            "ErrorCode": event.get('error_code')
        })

    def rtp_disable(self, event):
        self.for_siem.update({
            "EventName": f'def_{event.get("common_type")}',
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "EventTime": event.get("action_time"),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "SensorName": f'av_{event.get("av")}',
            "ModuleName": "Состояние защиты",
            "Block": event.get("block"),
            "Action": event.get("action"),
            "ActionSuccess": event.get("action_success"),
            "ObjectType": "ProtectionStatus",
            "Severity": event.get("severity"),
            "Severity_desc": event.get("summary"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "HostName": event.get("comp_name"),
            "Mask": event.get("comp_net_mask"),
            "MAC": event.get("comp_mac"),
            "TypeActivity": "Other"
        })
        self.for_siem.update(self.__get_ips(event.get("comp_ip")))

    def post_transform_event(self, event):
        self.for_siem = {}
        self.__formater(event)
        return self.for_siem


class Symantec:
    def __init__(self):
        self.for_siem = {}

    def __formater(self, event):
        if event.get('common_type') in ['NETWORK', 'network']:
            self.network(event)
        if event.get('common_type') in ['MALWARE', 'malware']:
            self.file(event)
        if event.get('common_type') in ['DISABLE_PROTECTION']:
            self.rtp_disable(event)

    def network(self, event):
        self.for_siem.update({
            "EventName": "sep_network",
            "EventType": event.get('siem_event_type'),
            "Type": event.get('type'),
            "Type2": event.get('type2'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_sep",
            "ModuleName": "Защита от сетевых атак",
            "Block": event.get("block"),
            "Action": "NetworkAttack",
            "Signatureid": event.get("signatureid"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("event_type_display_name"),
            "Deleted": event.get("deleted"),
            "Proto": event.get("proto"),
            "Port": event.get("port"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "SourceIP": event.get("attacker_ip"),
            "UserName": event.get("user_name"),
            # "UserDomainName": event.get("userdomainname"),
            "TypeActivity": "NetworkAttack",
        })

    def file(self, event):
        self.for_siem.update({
            "EventName": "sep_file",
            "EventType": event.get('siem_event_type'),
            "Type": event.get('type'),
            "Type2": event.get('type2'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_sep",
            "ModuleName": "Файловый Антивирус",
            "Block": event.get("block"),
            "Action": event.get("action"),
            "ObjectType": "MalwareObject",
            "ObjectPath": event.get("file_path"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "Sha256": event.get("object_sha256"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "TypeActivity": "Other",
            "UserName": event.get('user_name'),
            # "UserDomainName": tudn
        })

    def rtp_disable(self, event):
        self.for_siem.update({
            "EventName": "sep_rtp_disable",
            "EventType": event.get('siem_event_type'),
            "Type": event.get('type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_sep",
            "ModuleName": "Состояние защиты",
            "Block": event.get("block"),
            "Action": event.get("action"),
            "ObjectType": "ProtectionStatus",
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "TypeActivity": event.get("action"),
            "UserName": event.get('user_name'),
            # "UserDomainName": tudn
        })

    def post_transform_event(self, event):
        self.for_siem = {}
        self.__formater(event)
        return self.for_siem


class Eset:
    def __init__(self):
        self.for_siem = {}

    def __formater(self, event):
        if event.get('common_type') == 'network':
            self.network(event)
        if event.get('common_type') == 'file':
            self.file(event)

    def network(self, event):
        self.for_siem.update({
            "EventName": "eset_network",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_eset",
            "ModuleName": "Защита от сетевых атак",
            # "Block": event.get("block"),
            "Action": "NetworkAttack",
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "Src_ip": event.get("src_ip"),
            "Src_port": event.get("src_port"),
            "Dst_ip": event.get("dst_ip"),
            "Dst_port": event.get("dst_port"),
            "Proto": event.get("proto"),
            "FQDN": event.get("comp_fqdn"),
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "SourceIP": event.get("attacker_ip"),
            "UserName": event.get("user_name"),
            "TypeActivity": "NetworkAttack",
        })

    def file(self, event):
        self.for_siem.update({
            "EventName": "eset_file",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_eset",
            "ModuleName": "Файловый Антивирус",
            # "Block": event.get("block"),
            "Action": "Detected",
            "ObjectType": "MalwareObject",
            "ObjectPath": event.get("file_path"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "Sha256": event.get("sha256"),
            "FQDN": event.get("comp_fqdn"),
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "TypeActivity": "Other",
            "UserName": event.get('src_user_name'),
            # "UserDomainName": tudn
        })

    def post_transform_event(self, event):
        self.for_siem = {}
        self.__formater(event)
        return self.for_siem


class Kaspersky:
    def __init__(self):
        self.for_siem = {}

    def __formater(self, event):
        if event.get('common_type') == 'http_reputation':
            self.http_reputation(event)
        if event.get('common_type') == 'http_malware':
            self.http_malware(event)
        if event.get('common_type') == 'email_malware_from':
            self.email_malware_from(event)
        if event.get('common_type') == 'email_malware_to':
            self.email_malware_to(event)
        if event.get('common_type') == 'email_policy_from':
            self.email_policy_from(event)
        if event.get('common_type') == 'email_policy_to':
            self.email_policy_to(event)
        if event.get('common_type') == 'network':
            self.network(event)
        if event.get('common_type') == 'file':
            self.file(event)
        if event.get('common_type') == 'file2':
            self.file2(event)
        if event.get('common_type') == 'file3':
            self.file3(event)
        if event.get('common_type') == 'registry':
            self.registry(event)
        if event.get('common_type') == 'memory_obj':
            self.memory_obj(event)
        if event.get('common_type') == 'rtp_disable':
            self.rtp_disable(event)

    def http_reputation(self, event):
        tun = None
        tudn = None
        if event.get('username'):
            _un = event['username'].split('\\')
            if len(_un) > 1:
                tun = _un[1]
                tudn = _un[0]

        self.for_siem.update({
            "EventName": "kes_http_reputation",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Other",
            "ObjectType": "URL",
            "URL": event.get("intrusion_url"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("sig_descr"),
            "Deleted": event.get("deleted"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "UserName": tun,
            "UserDomainName": tudn,
            "TypeActivity": "Reputation"
        })

    def http_malware(self, event):
        tun = None
        tudn = None
        if event.get('username'):
            _un = event['username'].split('\\')
            if len(_un) > 1:
                tun = _un[1]
                tudn = _un[0]
        signature = event.get("signature")
        # ссылки прилетают в par5, можно было бы сделать условие по par8 (в зависимости от типа угрозы),
        # но не факт, что сигнатуры только по троянам
        for word in ["http://", "https://"]:
            if word in event.get("signature"):
                signature = None
        self.for_siem.update({
            "EventName": "kes_http_malware",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "detected",
            "ObjectType": "URL",
            "URL": event.get("intrusion_url"),
            "Severity": event.get("severity"),
            "Signature": signature,
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "Sha256": event.get("sha256"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "UserName": tun,
            "UserDomainName": tudn,
            "TypeActivity": "NetworkAttack"
        })  # TODO: sha256 в таких событиях всегда None

    def email_malware_from(self, event):
        tun = None
        tudn = None
        if event.get('username'):
            _un = event['username'].split('\\')
            if len(_un) > 1:
                tun = _un[1]
                tudn = _un[0]

        self.for_siem.update({
            "EventName": "kes_email_malware_from",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Detected",
            "ObjectType": "MailAttachment",
            "MailSubject": event.get("mail_subject"),
            "ObjectName": event.get("object_name"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "Sha256": event.get("sha256"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "UserName": tun,
            "UserDomainName": tudn,
            "OtherInformation": event.get("other_information"),
            "TypeActivity": "MalwareDistribution"
        })

    def email_malware_to(self, event):
        tun = None
        tudn = None
        if event.get('username'):
            _un = event['username'].split('\\')
            if len(_un) > 1:
                tun = _un[1]
                tudn = _un[0]

        self.for_siem.update({
            "EventName": "kes_email_malware_to",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Send",
            "ObjectType": "MailAttachment",
            "MailSubject": event.get("mail_subject"),
            "ObjectName": event.get("object_name"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "Sha256": event.get("sha256"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "OtherInformation": event.get("other_information"),
            "TypeActivity": "MalwareDistribution",
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "UserName": tun,
            "UserDomainName": tudn

        })

    def email_policy_from(self, event):
        tun = None
        tudn = None
        if event.get('username'):
            _un = event['username'].split('\\')
            if len(_un) > 1:
                tun = _un[1]
                tudn = _un[0]

        self.for_siem.update({
            "EventName": "kes_email_policy_from",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Detected",
            "ObjectType": "MailAttachment",
            "MailSubject": event.get("mail_subject"),
            "ObjectName": event.get("object_name"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": "",
            "Deleted": event.get("deleted"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "OtherInformation": event.get("other_information"),
            "TypeActivity": "MalwareDistribution",
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "UserName": tun,
            "UserDomainName": tudn

        })

    def email_policy_to(self, event):
        tun = None
        tudn = None
        if event.get('username'):
            _un = event['username'].split('\\')
            if len(_un) > 1:
                tun = _un[1]
                tudn = _un[0]

        self.for_siem.update({
            "EventName": "kes_email_policy_to",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Send",
            "ObjectType": "MailAttachment",
            "MailSubject": event.get("mail_subject"),
            "ObjectName": event.get("object_name"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": "",
            "Deleted": event.get("deleted"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "OtherInformation": event.get("other_information"),
            "TypeActivity": "MalwareDistribution",
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "UserName": tun,
            "UserDomainName": tudn

        })

    def network(self, event):
        tun = None
        if event.get("username"):
            tun = event.get("username")
        if event.get("username") and "(Активный пользователь)" in event.get("username"):
            tun = event["username"].replace(" (Активный пользователь)", "")

        self.for_siem.update({
            "EventName": "kes_network",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "NetworkAttack",
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "Proto": event.get("proto"),
            "Port": event.get("port"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "SourceIP": event.get("attacker_ip"),
            "UserName": tun,
            "UserDomainName": event.get("userdomainname"),
            "TypeActivity": "NetworkAttack",
        })

    def file(self, event):
        tun = None
        tudn = None
        if event.get('username'):
            _un = event['username'].split('\\')
            if len(_un) > 1:
                tun = _un[1]
                tudn = _un[0]

        self.for_siem.update({
            "EventName": "kes_file",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Detected",
            "ObjectType": "MalwareObject",
            "ObjectPath": event.get("object_path"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "Sha256": event.get("sha256"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "TypeActivity": "Other",
            "UserName": tun,
            "UserDomainName": tudn
        })

    def file2(self, event):
        tun = None
        tudn = None
        if event.get('username'):
            _un = event['username'].split('\\')
            if len(_un) > 1:
                tun = _un[1]
                tudn = _un[0]

        self.for_siem.update({
            "EventName": "kes_file2",
            "EventType": "66",
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Detected",
            "ObjectType": "File",
            "ObjectPath": event.get("object_path"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "Sha256": event.get("sha256"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "TypeActivity": "Other",
            "UserName": event.get("username"),
            "UserDomainName": event.get("userdom"),
        })

    def file3(self, event):
        self.for_siem.update({
            "EventName": "kes_file3",
            "EventType": "66",
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Detected",
            "ObjectType": "File",
            "ObjectPath": event.get("object_path"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "Sha256": event.get("sha256"),
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "TypeActivity": "Other",
            "UserName": event.get("username"),
            "UserDomainName": event.get("userdom"),
        })

    def registry(self, event):
        tun = None
        tudn = None
        if event.get('username'):
            _un = event['username'].split('\\')
            if len(_un) > 1:
                tun = _un[1]
                tudn = _un[0]

        self.for_siem.update({
            "EventName": "kes_Registry",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Detected",
            "ObjectType": "MalwareObject",
            "ObjectPath": event.get("object_path"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "TypeActivity": "Other",
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "UserName": tun,
            "UserDomainName": tudn,
        })

    def memory_obj(self, event):
        tun = None
        tudn = None
        if event.get('username'):
            _un = event['username'].split('\\')
            if len(_un) > 1:
                tun = _un[1]
                tudn = _un[0]

        self.for_siem.update({
            "EventName": "kes_Memory_obj",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Detected",
            "ObjectType": "MalwareObject",
            "ObjectPath": event.get("object_path"),
            "Signature": event.get("signature"),
            "Severity": event.get("severity"),
            "SignatureDescription": event.get("wstr_type"),
            "Deleted": event.get("deleted"),
            "TypeActivity": "Other",
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip"),
            "UserName": tun,
            "UserDomainName": tudn,
        })

    def rtp_disable(self, event):
        self.for_siem.update({
            "EventName": "kes_rtp_disable",
            "EventType": event.get('siem_event_type'),
            "Organization": event.get('organization'),
            "DetectionTime": event.get("dt"),
            "ID": event.get("event_id"),
            "EventTime": event.get("dt"),
            "SensorName": "av_kes",
            "ModuleName": event.get("task_display_name"),
            "Block": event.get("block"),
            "Action": "Detected",
            "ObjectType": "ProtectionStatus",
            "Severity": event.get("severity"),
            "Deleted": event.get("deleted"),
            "TypeActivity": "Detected",
            "FQDN": f'{event.get("comp_name")}.{event.get("comp_dom")}',
            "HostName": event.get("comp_name"),
            "HostDomain": event.get("comp_dom"),
            "IP": event.get("comp_ip")
        })

    def post_transform_event(self, event):
        self.for_siem = {}
        self.__formater(event)
        return self.for_siem
