from socutils import kafkaconn


class KafkaExceptions(Exception):
    pass


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Producer(metaclass=Singleton):
    """ Отправляем событие в кафку."""

    def __init__(self, auth, servers, **auth_settings):
        self.producer = None
        auth = kafkaconn.auth.Auth(auth, **auth_settings)
        self.producer = kafkaconn.kafkaconnector.Producer(servers=servers,
                                                          auth_params=auth.get_params())
        self.producer.create_producer()

    def send(self, topic, data):
        if not isinstance(topic, str):
            raise KafkaExceptions('Unexpected topic value')

        if not isinstance(data, dict):
            raise KafkaExceptions('Data must be a dict')

        self.producer.send_json(topic=topic, json_data=data)

    def async_send(self, topic, data):
        if not isinstance(topic, str):
            raise KafkaExceptions('Unexpected topic value')

        if not isinstance(data, dict):
            raise KafkaExceptions('Data must be a dict')

        self.producer.send_json_callback(topic, data)
        self.producer.flush()
