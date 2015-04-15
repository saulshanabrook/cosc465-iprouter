import collections
import functools
import types


def wrap_container(container_class, log):
    '''
    Returns a subclass of `container_class` that will call log for any setitem.

    It will also change the name of subconatiners if it is a defaultdict, so
    that they contain the name of the parent object for loggin.
    '''
    if container_class == collections.deque:
        return wrap_deque(log)

    def __setitem__(self, k, v):
        log('{}[{}]={}'.format(self.__name__, k, v))
        super(LogContainer, self).__setitem__(k, v)

    def __getitem__(self, k):
        value = super(LogContainer, self).__getitem__(k)
        if isinstance(self, collections.defaultdict):
            value.__name__ = '{}[{}]'.format(self.__name__, str(k))
        return value

    LogContainer = type(
        'Log{}'.format(container_class.__name__),
        (container_class,),
        {'__setitem__': __setitem__, '__getitem__': __getitem__}
    )
    return LogContainer


def wrap_deque(log):
    def appendleft(self, v):
        log('{}.appendleft({})'.format(self.__name__, v))
        super(LogDequeue, self).appendleft(v)

    def pop(self, v):
        log('{}.pop({})'.format(self.__name__, v))
        super(LogDequeue, self).pop(v)

    LogDequeue = type(
        'LogDequeue',
        (collections.deque,),
        {'appendleft': appendleft, 'pop': pop}
    )
    return LogDequeue


class DebugMetaClass(type):
    '''
    Logs the arguments and return values for every method call.

    Also log's when dictionary and list attributes are changed.
    '''

    level = 0

    def __init__(cls, name, bases, namespace, log_function):
        type.__init__(cls, name, bases, namespace)

    def __new__(cls, name, bases, namespace, log_function):
        cls.base_log_function = log_function

        for name, value in namespace.items():
            log_container = functools.partial(wrap_container, log=cls.log)
            if isinstance(value, types.FunctionType):
                new_value = cls.make_log(value)
            elif isinstance(value, collections.defaultdict):
                logged_factory = log_container(value.default_factory)
                new_value = log_container(collections.defaultdict)(logged_factory)
            elif isinstance(value, dict):
                new_value = log_container(dict)(**value)
            elif isinstance(value, list):
                new_value = log_container(list)(*value)
            else:
                continue
            new_value.__name__ = name
            namespace[name] = new_value
        return type.__new__(cls, name, bases, namespace)

    @classmethod
    def log(cls, message):
        cls.base_log_function(' ' * cls.level + message)

    @classmethod
    def make_log(cls, func):
        @functools.wraps(func)
        def log_wrapper(*args, **kwargs):
            cls.log_method_call(func, *args, **kwargs)
            cls.level += 1
            result = func(*args, **kwargs)
            cls.level -= 1
            cls.log_method_return(result)
            return result
        return log_wrapper

    @classmethod
    def log_method_call(cls, func, *args, **kwargs):
        arguments = ', '.join(
            list(map(str, args[1:])) + ['{}={}'.format(str(k), str(v)) for k, v in kwargs.items()]
        )
        cls.log('{}({})'.format(func.__name__, arguments))

    @classmethod
    def log_method_return(cls, result):
        cls.log('->{}'.format(str(result)))
