"""PluginManager -- handles the loading of plugins and submodules"""

import sys
import os
import glob
import imp
import inspect
# import plugin name spaces to prevent runtime warnings
import foghornd.plugins.listhandler
import foghornd.plugins.logger
import foghornd.plugins.hooks
# Silence flake8 warnings
assert foghornd.plugins.listhandler
assert foghornd.plugins.logger
assert foghornd.plugins.hooks


class PluginManager(object):
    """This class provides a loader for plugins"""
    modules = {}

    def __init__(self, base, path="./plugins/", pattern="*.py", class_type=None):
        self.load_plugins(base, path, pattern, class_type)

    def new(self, plugin, *args, **kwargs):
        """Create a new plugin type, passing extra args to constructor"""
        if plugin in self.modules.keys():
            return self.modules[plugin](*args, **kwargs)

    def load_plugins(self, base, path, pattern="*.py", class_type=None):
        """
        Load all modules from a path and return a dictionary of those
        values with the key being module name and they value being the
        caller to create a new object.
        """
        path = os.path.join(path, pattern)
        modules = {}
        for infile in glob.glob(path):
            basename = os.path.basename(infile)
            if basename == "__init__.py":
                continue
            plugin_name = basename[:-3]
            plugin_namespace = "%s.%s" % (base, plugin_name)
            if plugin_namespace in sys.modules:
                # Already loaded
                plugin = sys.modules[plugin_namespace]
            else:
                plugin = imp.load_source(plugin_namespace, infile)
            caller = getattr(plugin, plugin_name, None)
            if caller is None:
                raise ImportError("Class not found:", plugin_name, plugin)
            if class_type:
                if not inherits_from(caller, class_type):
                    raise ImportError("Wrong class type:", plugin_name, plugin)
            modules[plugin_name] = caller
            self.modules = modules


def inherits_from(child, parent_name):
    """Check if a class inherits from a parent class"""
    if inspect.isclass(child):
        if parent_name in [c.__name__ for c in inspect.getmro(child)[1:]]:
            return True
    return False
