import logging


def ip(string: str) -> bool:
    """ Return true if str can be parsed like ip """
    parts = string.split('.')
    if len(parts) != 4:
        raise ValueError('Wrong octets count')
    for part in parts:
        if not 0 <= int(part) <= 255:
            raise ValueError('Wrong octets value')
    return string


def get_logger():
    """ Get root logger """
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger('dns-fc')
    return log
