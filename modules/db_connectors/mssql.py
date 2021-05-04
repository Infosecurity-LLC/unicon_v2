import pymssql
import logging
import sys

logger = logging.getLogger(__name__)


class DbaseException(Exception):
    pass


class SelectorMSSQL:
    def __init__(self, device, db_setting):
        self.cursor = None
        self.device = device
        try:
            self.connection = pymssql.connect(server=db_setting['server'],
                                              port=db_setting['port'],
                                              user=db_setting['user'],
                                              password=db_setting['password'],
                                              database=db_setting['database'])
        except pymssql.OperationalError as err:
            logger.error(f"[{device}] Не удалось подключиться к БД")
            sys.exit(1)
            # raise DbaseException(f'[{self.device}] Dbase server connection failed {err}')

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.connection.close()

    def raw_query(self, query):
        self.cursor = self.connection.cursor()
        try:
            self.cursor.execute(query)
        except pymssql.ProgrammingError:
            raise DbaseException(
                f'[{self.device}] SQL ProgrammingError at dbase.select function. Error in sql select: {query}')
        return self.cursor
