# -*- coding: utf-8 -*-
"""
Created on Mon Jan  6 18:23:14 2014

@author: slarinier
"""

from __future__ import unicode_literals
from settings import CEV_ROOT
import os
import inspect
import importlib
import pkgutil


def _list_packages():
    directories = []
    lib_dir = CEV_ROOT
    if lib_dir.endswith('.zip'):
        lib_dir = lib_dir[0:-4]
    for root, dirnames, filenames in os.walk(lib_dir):
        directories = dirnames
        break

    return directories


def _iter_modules(packages):
    for p in packages:
        imports = []
        try:
            for path_import in __import__(p).__path__:
                imports.append(path_import.replace('.zip', ''))
        except ImportError:
            pass

        for importer, modname, ispkg in pkgutil.iter_modules(imports):
            # quick fix for winXP
            if 'psutil' not in p and not modname.endswith('ext'):
                yield importlib.import_module(p + '.' + modname)


def load_classes(module, os_name, release):
    for name, class_to_load in inspect.getmembers(module, inspect.isclass):
        if name.find(os_name + 'All') != -1:
            yield class_to_load
        elif name.find(os_name + release) != -1:
            yield class_to_load


def load_modules(filters, output_dir):
    directories = _list_packages()
    __filter_packages(filters, directories, output_dir)
    return _iter_modules(directories)


def list_packages(self, filters, os_name, release):
    """List available and activated packages"""
    result = {}
    packages = _list_packages()

    copy = packages[:]
    for p in copy:
        if p.find('.') == 0:
            packages.remove(p)

    activated_packages = list(packages)
    activated_packages = self.__filter_packages(filters, activated_packages, '')

    for module in _iter_modules(packages):
        classes = load_classes(module, os_name, release)
        for cl in classes:
            activated = False
            if module.__package__ in activated_packages:
                activated = True
            result[module.__package__] = activated
            break
    return result


def __filter_packages(modules, directories, output_dir):
    # Remove 'intel', 'dump' and 'filecatcher' if they are not explicitely specified
    for m in ['intel', 'dump', 'filecatcher']:
        if m in directories and m not in modules:
            directories.remove(m)

    # Remove everything that is not a valid CE package
    copy = directories[:]
    for d in copy:
        if d.find('.') == 0 or d.startswith('_') or d == output_dir:
            directories.remove(d)

    # Remove everything not specified in module, unless module contains 'all'
    if 'all' not in modules:
        copy = directories[:]
        for d in copy:
            if d not in modules:
                directories.remove(d)

    # If dump is specified, put it in first position
    if 'dump' in directories:
        directories.remove('dump')
        directories.insert(0, 'dump')

    return directories