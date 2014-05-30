#!/usr/bin/python


"""Parses Umbra configuration"""


import json
import sys


class ConfigValidationException(Exception):
    pass


def is_string(s):
    return isinstance(s, unicode) or isinstance(s, str)


def is_page(s):
    return is_string(s) and len(s) > 0 and s[0] == '/'


def is_list_of(x, typeFunc, minLen = 0):
    if type(x) is not list:
        return False
    return (reduce(lambda a,b: a and typeFunc(b), x, True)
            and minLen <= len(x))


def assert_parse(value, msg):
    if not value:
        raise ConfigValidationException(msg)


class Option:
    def __init__(self, name, defaultValue=None):
        self.name = name
        self.value = defaultValue
        self.valueHasBeenSet = False

    def validate(self):
        raise Exception('Validate not implemented')

    def setValue(self, value):
        self.value = value
        self.valueHasBeenSet = True

    def getDesc(self):
        s = '%s %s:' % (self.__class__.__name__,
                self.name)
        if hasattr(self, 'value'):
            s += '\nvaluetype=%s,\n value=%s' % (self.value.__class__.__name__,
                                               repr(self.value))
        return s
    
    def assrt(self, value, msg):
        assert_parse(value, '<' + self.getDesc() + '>:\n' + msg)


class BoolOption(Option):
    def validate(self):
        self.assrt(isinstance(self.value, bool), 'Invalid Boolean value "%s"' %
                   repr(self.value))


class PosIntOption(Option):
    def validate(self):
        self.assrt(isinstance(self.value, int) or isinstance(self.value, long),
                   'Must be integer or long')
        self.assrt(self.value > 0, 'Must be greater than 0')


class StringOption(Option):
    def validate(self):
        self.assrt(is_string(self.value), 'Value "%s" is not string' %
                   repr(self.value))


class StringArrOption(Option):
    def __init__(self, name, default=[], minLen=0, allowedVals=None,
                 isElementValid=None):
        Option.__init__(self, name, default)
        self.allowedVals = allowedVals
        self.minLen = minLen
        self.isElementValid = isElementValid

    def validate(self):
        self.assrt(is_list_of(self.value, is_string, self.minLen),
                   'Must be list')
        if self.allowedVals != None:
            self.assrt(set(self.value).issubset(self.allowedVals),
                       'Elements must be in allowed set: %s' %
                           repr(self.allowedVals))
        if self.isElementValid != None:
            for x in self.value:
                self.assrt(self.isElementValid(x), 'Invalid element "%s"' %
                           repr(x))


class MultiOption(Option):
    def __init__(self, name, requiredConf, optionalConf):
        self.name = name
        self.valueHasBeenSet = False
        self.requiredConf = requiredConf
        self.optionalConf = optionalConf
        self.requiredName2Conf = {x.name:x for x in self.requiredConf}
        self.optionalName2Conf = {x.name:x for x in self.optionalConf}
        for x in self.requiredConf.union(self.optionalConf):
            self.assrt(isinstance(x, Option), "Must take Options")

    def validate(self):
        for x in self.requiredConf:
            self.assrt(x.valueHasBeenSet, 'Option %s has not been specified' %
                       x.name)
            x.validate()
        for x in self.optionalConf:
            if x.valueHasBeenSet:
                x.validate()

    def setValue(self, value):
        Option.setValue(self, value)

        # Create mapping between option name and option object
        name2conf = self._getName2Conf()

        # Set option values
        for optname,optval in self.value.items():
            self.assrt(optname in name2conf, 'Unknown option "%s"' % optname)
            name2conf[optname].setValue(optval)

    def _getName2Conf(self):
        name2conf = self.requiredName2Conf.copy()
        name2conf.update(self.optionalName2Conf)
        return name2conf


class NamedOptionSet(MultiOption):
    def __init__(self, name, requiredConf, optionalConf):
        MultiOption.__init__(self, name, requiredConf, optionalConf)
        self.suboptions = {}

    def setValue(self, value):
        Option.setValue(self, value)
        for path,conf in value.items():
            page_conf = MultiOption(self.name + ' ' + path, self.requiredConf,
                                     self.optionalConf)
            page_conf.setValue(conf)
            self.suboptions[path] = page_conf


class PageConfOption(NamedOptionSet):
    def validate(self):
        for path,page_conf in self.suboptions.items():
            self.assrt(is_page(path),
                       'Path "%s" is not valid, must start with a "/"' % path)
            page_conf.validate()


class ParamsOption(NamedOptionSet):
     def validate(self):
         for param,param_conf in self.suboptions.items():
            self.assrt(is_string(param),
                       'Param "%s" is not valid, must be string' % param)
            param_conf.validate()


# Configuration specification
param_conf_required = set()
param_conf_optional = {
        StringArrOption('allowed_param_chars', [], 0,
                ['safe_ascii', 'alpha', 'alpha_lower', 'alpha_upper', 'digit']),
        PosIntOption('max_param_len', 20),
        StringOption('whitelist', '')
        }

page_conf_required = set()
page_conf_optional = {
        PosIntOption('max_header_field_len', 120),
        PosIntOption('max_header_len', 120),
        PosIntOption('max_post_payload_len', 120),
        ParamsOption('params', param_conf_required, param_conf_optional),
        BoolOption('params_allowed', False),
        BoolOption('redirect_to_https', True),
        StringArrOption('request_types', ['HEAD', 'GET'], 0,
                        ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'TRACE']),
        BoolOption('requires_login', True)
        }.union(param_conf_optional)

global_conf_required = {
        StringOption('https_certificate'),
        StringOption('https_private_key'),
        StringArrOption('successful_login_pages', minLen=1)
        }
global_conf_optional = set()

toplevel_conf = MultiOption('toplevel', {
        MultiOption('global_config', global_conf_required,
                    global_conf_optional),
        PageConfOption('page_config', page_conf_required, page_conf_optional)
        }, set())


def parse_config(config_file, output_header):
    print 'Parsing config file "%s"' % config_file
    with open(config_file, 'r') as f:
        conf = json.load(f)
        toplevel_conf.setValue(conf)
    toplevel_conf.validate()
    print '[done]'

    
def main():
    if len(sys.argv) != 3:
        print 'Usage: %s CONFIG OUTPUT_HEADER' % sys.argv[0]
        sys.exit(1)
    config_file, output_header = tuple(sys.argv[1:])
    parse_config(config_file, output_header)


if __name__ == '__main__':
    main()
