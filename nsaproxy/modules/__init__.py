# -*- coding: utf-8 -*-
# Copyright (C) 2018-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later

import re as _re
import os as _os

def _package_path():
    return _os.path.dirname(_os.path.abspath(__file__))

def _is_package_child(path, name):
    full = _os.path.join(path, name)
    if _os.path.isdir(full):
        for sub in _os.listdir(full):
            if _re.match(r"__init__\.py[a-z]?$", sub):
                return True
        else:
            return False
    else:
        return _re.search(r"\.py[a-z]*$", name) \
               and '__init__' not in name

# Python doesn't really want us to do that because of
# compatibility with stupid operating systems, but thanks
# to this function we can do it anyway... :)
def _get_module_list(path):
    return list(set([_re.sub(r"\.py[a-z]?$", "", name)
                     for name in _os.listdir(path)
                     if _is_package_child(path, name)]))

__all__ = _get_module_list(_package_path())
