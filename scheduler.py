import time
import logging
from connector import StartTime
import connector
import console_starter as console
import subprocess
import os
import sys

logger = logging.getLogger("scheduler")
logger.setLevel(connector.setting['logging']['basic_level'])
stream_handler = logging.StreamHandler()
stream_handler.setLevel(connector.setting['logging']['term_level'])
stream_handler.addFilter(connector.ContextFilter())
stream_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(levelname)-10s - %(hostname)s - [in %(pathname)s:%(lineno)d]: - %(message)s'))
logger.addHandler(stream_handler)
'''
    Ищем в базе время последнего запуска, (если его нет, создаём первую запись с настоящим временем и статусом 1)
    Если с момента последнего запуска времени прошло меньше чем необходимая start_timeout, то ждём и повторяем сналача
    Если прошло времени больше чем start_timeout, создаём запись о новом старте со статусом 0
    В случае удачного завершения работы скрипта меняем статус на 1, ждём и повторяем с начала
'''

start_time = StartTime()


def get_sensors():
    """ Получаем список девайсов, с которых собирать данные """
    return list(connector.setting['sensors'].keys())


def do_start(sensor):
    """ Проверяем, нужно ли стартовать сбор событий с сенсора"""
    last_start_dt = start_time.get_last_start(sensor)
    difference_time = connector.datetime.now() - last_start_dt
    if difference_time.seconds < connector.setting['sensors'][sensor].get('start_timeout') * 60:
        return False, False
    new_ls_id = start_time.create_new_last_start(sensor)
    return True, new_ls_id


sensors = get_sensors()
sensor_name = sensors[0]  # костыль пока не замучу многопоточность
logger.info('Start unicon')
while True:
    start, new_ls_id = do_start(sensor_name)  # проверка на таймаут, стартовать или нет
    if not start:
        logger.debug(f'[{sensor_name}] wait')
        time.sleep(10)
        continue
    try:
        child = os.path.join(os.path.dirname(__file__), 'console_starter.py')
        command = [sys.executable, child, '-s', sensor_name]
        logger.info(f'Запускаю сборщик')
        pipe = subprocess.Popen(command, stdin=subprocess.PIPE)
        pipe.wait()
        logger.info(f'Сборщик сделал своё дело')
    except Exception as err:
        logger.exception(err)
        time.sleep(10)
        continue

    if new_ls_id:
        start_time.confirm_new_last_start(sensor_name, new_ls_id)
    logger.info(
        '[{}] ждём {} минут'.format(sensor_name, connector.setting['sensors'][sensor_name].get('start_timeout')))
