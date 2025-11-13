# -*- coding: utf-8 -*-
"""Python2 f-string like behavior"""
from __future__ import print_function
import inspect
import re

def fstr(expr, params=()):
    # Replace each {expression} with the variable value.
    def replacer(match):
        index = int(match.group(1))
        try:
            return str(params[index])
        except Exception as e:
            raise ValueError("Error evaluating expression " + str(index) + str(e))
    out = re.sub(r'\{([^}]*)\}', replacer, expr)
    return out

class fstr2(object):
    """String formatter based on Python 3.6 'f' strings

    `F` will automatically format anything between two
    braces (ie: {{ ... }}) when printed. The original
    representation of the string is kept as well and
    printed with `print(repr(f_string))`.

    There is also a stand alone method which takes a
    `regex` and a `string` for input and returns the
    string with all pattern matches replaced.

    Attributes:
        _string: the string to be formatted
        text: the newly formatted string
    """
    _regex = re.compile(r"\{([^{}]+)\}", re.S)

    def __init__(self, s, regex=None):
        """Init `F` with string `s`"""
        self.regex = regex or self._regex
        self._string = s
        self.f_locals = self.original_caller.f_locals
        self.f_globals = self.original_caller.f_globals
        self.text = self._find_and_replace(s)

    @property
    def original_caller(self):
        names = []
        frames = []
        frame = inspect.currentframe()
        while True:
            try:
                frame = frame.f_back
                name = frame.f_code.co_name
                names.append(name)
                frames.append(frame)
            except Exception:
                break
        return frames[-2]

    def _find_and_replace(self, s):
        """Evaluates and returns all occurrences of `regex` in `s`"""
        return re.sub(self._regex, self._clean_and_eval, s)

    def _clean_and_eval(self, m):
        """Remove surrounding braces and whitespace from regex match `m`,
            evaluate, and return the result as a string.

        """
        replaced = m.group()[1:][:-1].strip()
        try:
            result = str(eval(replaced))
            return result
        except (TypeError, NameError, SyntaxError):
            try:
                result = str(eval(replaced, self.f_locals, self.f_globals))
                return result
            except (TypeError, NameError, SyntaxError):
                raise ValueError("Can't find replacement for { %s }, sorry." % replaced)

    def __str__(self):
        return str(self.text)

    def __repr__(self):
        return str(self._string)

