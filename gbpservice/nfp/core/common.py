import os
import sys


def _is_class(obj):
    return 'class' in str(type(obj))


def _name(obj):
    """ Helper method to construct name of an object.

    'module.class' if object is of type 'class'
    'module.class.method' if object is of type 'method'
    """
    # If it is callable, then it is a method
    if callable(obj):
        return "{0}.{1}.{2}".format(
            type(obj.im_self).__module__,
            type(obj.im_self).__name__,
            obj.__name__)
    # If obj is of type class
    elif _is_class(obj):
        return "{0}.{1}".format(
            type(obj).__module__,
            type(obj).__name__)
    else:
        return obj.__name__


def identify(obj):
    """ Helper method to display identify an object.

    Useful for logging. Decodes based on the type of obj.
    Supports 'class' & 'method' types for now.
    """
    try:
        return "(%s)" % (_name(obj))
    except:
        """ Some unknown type, returning empty """
        return ""
