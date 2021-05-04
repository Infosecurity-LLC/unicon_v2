import argparse
import connector
import logging

'''
    Запуск из консоли старый вариант
'''
logger = logging.getLogger("console_starter")


def start(sensor, event_id=None, environment=None):
    def get_sensors():
        """ Получаем список девайсов, с которых собирать данные """
        if sensor:
            return [sensor]
        return list(connector.setting['sensors'].keys())

    def standart_start():
        """ Срандартный запуск сбора и отправки данных"""
        work_time = connector.WorkTime()
        sensors = get_sensors()
        for device in sensors:
            last_position, new_lp_id = work_time.get_last_position(device)
            connector.logger.info('Start work for {}'.format(device))
            collect = connector.collect(device=device, last_position=last_position)
            connector.process(device=device)
            if collect:
                work_time.update_last_position(device, new_lp_id)

    def manual_start(_event_id, _environment):
        """ Забираем событие по указанному вручную event_id """
        sensors = get_sensors()
        for device in sensors:
            connector.logger.info('Start work for {}'.format(device))
            connector.collect(device=device, event_id=_event_id, env=_environment)
            connector.process(device=device)

        connector.logger.info('Start AV connector')

    if not event_id:
        standart_start()
    elif event_id:
        manual_start(event_id, environment)

    connector.logger.info('AV connector end work\n')
    return True


def set_start_params(args):
    """
    Инициализация параметров для запуска
    :param args: 
    :return: 
    """
    if args.event_id and args.environment:
        sensor = None
        if args.sensor:
            sensor = args.sensor

        try:
            # сбор конкретного события
            start(sensor=sensor, event_id=args.event_id, environment=args.environment)
        except Exception as err:
            connector.logger.critical('CONNECTOR WAS STOPPED\n')
            connector.logger.exception(err)
            connector.sys.exit(1)
    elif args.sensor and args.event_id:
        connector.logger.error('If you want to sent event manually, you must send the parameters: -s -env -id')

    elif args.sensor:
        try:
            # сбор событий с конкретного сенсора
            start(sensor=args.sensor)
        except Exception as err:
            connector.logger.critical('CONNECTOR WAS STOPPED\n')
            connector.logger.exception(err)
            connector.sys.exit(1)
    else:
        try:
            # сбор событий со всех сенсоров
            start(sensor=None)
        except Exception as err:
            connector.logger.critical('CONNECTOR WAS STOPPED\n')
            connector.logger.exception(err)
            connector.sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--sensor', help='AV device name')
    parser.add_argument('-env', '--environment',
                        help='The event id which needs to be taken from the {sensor} AV database ')
    parser.add_argument('-id', '--event_id',
                        help='The event id which needs to be taken from the {sensor}{environment} AV database ')
    args = parser.parse_args()
    set_start_params(args=args)


if __name__ == '__main__':
    main()
