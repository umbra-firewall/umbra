#!/usr/bin/python


"""Parses Umbra configuration"""

# pylint: disable=too-few-public-methods, locally-disabled, no-self-use,star-args, too-many-arguments, too-many-instance-attributes, super-init-not-called, abstract-method

import json
import os
import re
import struct
import sys
from copy import deepcopy


class ConfigValidationException(Exception):
    """Configuration is not well-formed"""
    pass


def is_string(obj):
    """Returns true if object is a string-like object"""
    return isinstance(obj, unicode) or isinstance(obj, str)


def is_page(obj):
    """Returns true if string-like object is a valid web path"""
    return is_string(obj) and len(obj) > 0 and obj[0] == '/'


def is_list_of(list_, type_func, min_len=0):
    """
    Returns boolean indicating if list contains only elements of the type
    checked by type_func.
    """
    if type(list_) is not list:
        return False
    return (reduce(lambda a, b: a and type_func(b), list_, True)
            and min_len <= len(list_))


def assert_parse(value, msg):
    """Assert value is true while parsing"""
    if not value:
        raise ConfigValidationException(msg)


def c_str_repr(str_):
    """Returns representation of string in C (without quotes)"""
    def byte_to_repr(char_):
        """Converts byte to C code string representation"""
        char_val = ord(char_)
        if char_ in ['"', '\\', '\r', '\n']:
            return '\\' + chr(char_val)
        elif (ord(' ') <= char_val <= ord('^') or char_val == ord('_') or
              ord('a') <= char_val <= ord('~')):
            return chr(char_val)
        else:
            return '\\x%02x' % char_val

    return '"%s"' % ''.join((byte_to_repr(x) for x in str_))


def dict_updated(dict_, entry):
    """Returns copy of dict d with updates in e"""
    ret = dict_.copy()
    ret.update(entry)
    return ret


class MacroDef(object):
    """Represents C macro definition"""

    def __init__(self, name, value):
        self.name = name
        self.value = value

    def to_string(self):
        """Returns C source representation"""
        return '#define %s %s\n' % (self.name, str(self.value))


class StructDef(object):
    """Represents C structure"""

    def __init__(self, name, elements):
        """
        Takes structure name and elements list of pairs

        Argument each element of elements is of the form (type, name)
        """
        self.name = name
        self.elements = elements

    def to_string(self):
        """Returns C source representation"""
        expand_elements = Option.expand_elements(self.elements)
        element_lines = ['    %s %s;' % x for x in expand_elements]
        element_lines.sort()
        parts = (['struct %s {' % self.name] +
                 element_lines +
                 ['};'])
        return '\n'.join(parts) + '\n'

    def get_prototype(self):
        """Returns C source prototype"""
        return 'struct %s;' % self.name


class VarInst(object):
    """Represents instance of variable"""

    instCount = 0

    def __init__(self, typestr, name, value):
        self.typestr = typestr
        self.name = name
        self.value = value

    def to_string(self):
        """Returns C source representation"""
        return '%s %s = %s;\n' % (self.typestr, self.name, self.value)

    @staticmethod
    def get_next_inst_name():
        """Returns the next instance name, ensuring unique names"""
        VarInst.instCount += 1
        return 'inst_%03d' % VarInst.instCount


class StringArrInst(VarInst):
    """Represents an instance of a C array of strings (char **)"""
    def __init__(self, name, value):
        VarInst.__init__(self, '', name, value)

    def to_string(self):
        """Returns C source definition"""
        array_body \
            = '{%s}' % ', '.join([c_str_repr(x) for x in self.value])
        return 'const char *%s[%d] = %s;\n' % (self.name, len(self.value),
                                               array_body)

    def to_proto_string(self):
        """Returns C source declaration"""
        return 'const char *%s[%d];\n' % (self.name, len(self.value))


class StructArrInst(VarInst):
    """Represents an instance of a C array of structs (char **)"""
    def __init__(self, value, struct_name):
        for struct_ in value:
            assert_parse(isinstance(struct_, StructInst), "Takes iterable of StructInsts")
        VarInst.__init__(self, '', VarInst.get_next_inst_name(), value)
        self.struct_name = struct_name

    def to_string(self):
        """Returns C source representation"""
        raise Exception('Call to_string_declaration() or to_string_initialize()')

    def to_string_declaration(self):
        """Returns C declaration source"""
        return 'struct %s %s[%d];\n' % (self.struct_name, self.name, len(self.value))

    def to_string_initialize(self, indent=4):
        """Returns C initialization source"""
        if len(self.value) == 0:
            return ''
        lines = []
        for i in xrange(len(self.value)):
            body_item = '%s[%d] = %s;' % (self.name, i, self.value[i].name)
            lines.append(indent * ' ' + body_item)
        return '\n'.join(lines)


class StructInst(VarInst):
    """Represents instance of a C struct"""


    def __init__(self, structDef, struct_name, inst_name=None):
        if inst_name == None:
            inst_name = VarInst.get_next_inst_name()
        VarInst.__init__(self, '', inst_name, None)
        structDef.set_instance_name(self.name)
        self.option = structDef
        self.struct_name = struct_name

    def to_string(self):
        """Returns C source representation"""
        struct_src = ['struct %s %s = {' % (self.get_struct_name(), self.name)]
        all_opts = list(self.option.get_all_options())
        all_opts.sort(key=lambda x: x.name)
        for opt in all_opts:
            for (_, name, value) in opt.get_elements_value():
                struct_src.append('    .%s = %s,' % (name, value))
        struct_src.append('};')
        return '\n'.join(struct_src) + '\n'

    def get_struct_name(self):
        """Returns struct name"""
        return self.struct_name


HEADER_TOP = """/* Autogenerated header, do not modify */

#ifndef UMBRA_DYN_CONFIG_HEADER
#define UMBRA_DYN_CONFIG_HEADER

#include <stdbool.h>

void init_config_vars();
\n\n"""

HEADER_END = "\n#endif\n"

DERIVED_MACRO_DEFS = """/* Derived macro definitions*/
#define PAGES_CONF_LEN (sizeof(pages_conf) / sizeof(*pages_conf))
#define ENABLE_PARAM_CHECKS (ENABLE_PARAM_LEN_CHECK || ENABLE_PARAM_WHITELIST_CHECK || ENABLE_CSRF_PROTECTION)
#define ENABLE_SESSION_TRACKING (ENABLE_CSRF_PROTECTION)
"""

INIT_FUNC_FORMAT = """void init_config_vars() {
%s
}
"""

BODY_TOP = """/* Autogenerated C file, do not modify */

#include "%s"
#include "http_util.h"
\n\n"""

class CodeHeader(object):
    """Holds information of code being generated"""
    def __init__(self):
        self.macro_defs = []
        self.struct_defs = []
        self.params_structs = []
        self.page_conf_structs = []
        self.var_defs = []
        self.params_arrays = []
        self.page_conf_arrays = []

    def write_config_header(self, header_file):
        """Write C header file"""
        header_file.write(HEADER_TOP)

        header_file.write('/* Macro definitions */\n')
        for macro in self.macro_defs:
            header_file.write(macro.to_string() + '\n')

        header_file.write('/* Struct prototypes */\n\n')
        for struct_def in self.struct_defs:
            header_file.write(struct_def.get_prototype() + '\n')
        header_file.write('\n')

        header_file.write('/* Struct definitions */\n\n')
        for struct_def in self.struct_defs:
            header_file.write(struct_def.to_string() + '\n')

        header_file.write('#define WHITELIST_PARAM_LEN %d\n' %
                          WhitelistOption.num_bytes)

        header_file.write('\n')

        header_file.write('/* Global variables */\n\n')
        for struct_def in self.page_conf_arrays:
            header_file.write("extern ")
            header_file.write(struct_def.to_string_declaration() + '\n')


        header_file.write('extern struct page_conf default_page_conf;\n')
        for var_def in self.var_defs:
            header_file.write('extern ')
            header_file.write(var_def.to_proto_string() + '\n')

        header_file.write(DERIVED_MACRO_DEFS + '\n')

        header_file.write(HEADER_END)

    def write_config_body(self, output_header, body_file):
        """Write C source file"""
        body_file.write(BODY_TOP % output_header)

        body_file.write('/* Variable definitions */\n\n')
        for var_def in self.var_defs:
            body_file.write(var_def.to_string() + '\n')

        body_file.write('/* Struct instances */\n\n')

        body_file.write('/* Params instances */\n\n')
        for param_struct in self.params_structs:
            body_file.write(param_struct.to_string() + '\n')

        body_file.write('/* Param arrays */\n\n')
        for param_arr in self.params_arrays:
            body_file.write(param_arr.to_string_declaration() + '\n')

        body_file.write('/* Page_conf instances */\n\n')
        for page_conf in self.page_conf_structs:
            body_file.write(page_conf.to_string() + '\n')

        body_file.write('/* Page_conf array */\n\n')
        for page_conf_arr in self.page_conf_arrays:
            body_file.write(page_conf_arr.to_string_declaration() + '\n')

        body_file.write('/* Initializer function */\n')
        body_file.write('void init_config_vars() {\n')
        for param_arr in self.params_arrays:
            initialize_string = param_arr.to_string_initialize()
            if initialize_string:
                body_file.write(initialize_string + '\n')
        body_file.write('\n')
        for page_conf in self.page_conf_arrays:
            initialize_string = page_conf.to_string_initialize()
            if initialize_string:
                body_file.write(initialize_string + '\n')
        body_file.write('}\n')

    def add_macro_def(self, name, value):
        """Add a macro definition"""
        self.macro_defs.append(MacroDef(name, value))

    def add_struct_def(self, struct_def):
        """Add a struct definition"""
        if struct_def.name in [x.name for x in self.struct_defs]:
            return
        self.struct_defs.append(struct_def)

    def add_page_conf_struct(self, inst):
        """Add a page_conf struct"""
        self.page_conf_structs.append(inst)

    def add_params_struct(self, inst):
        """Add a params struct"""
        self.params_structs.append(inst)

    def add_params_array(self, arr):
        """Add a params array"""
        if not isinstance(arr, StructArrInst):
            raise Exception("Must be type StructArrInst")
        self.params_arrays.append(arr)

    def add_page_conf_array(self, arr):
        """Add a page config array"""
        if not isinstance(arr, StructArrInst):
            raise Exception("Must be type StructArrInst")
        self.page_conf_arrays.append(arr)

    def add_var_def(self, var):
        """Add a variable definition"""
        self.var_defs.append(var)


class Option(object):
    """Represents simple configuration option"""
    def __init__(self, name, is_top_level=False, defaultValue=None):
        self.name = name
        self.value = defaultValue
        self.value_has_been_set = False
        self.is_top_level = is_top_level

    @staticmethod
    def expand_elements(elements):
        """Return sorted elements"""
        ret = []
        for elem in elements:
            ret += elem.get_elements()
        ret.sort()
        return ret

    @staticmethod
    def sort_struct_element_list(elem_list):
        """Sorts an element list by type"""
        elem_list.sort(key=lambda x: (x.get_ctype(), x.name))

    def validate(self):
        """Validates config"""
        raise Exception('Validate not implemented')

    def set_value(self, value):
        """Sets value"""
        self.value = value
        self.value_has_been_set = True

    def add_config(self, info):
        """Adds config"""
        raise NotImplementedError()

    def get_ctype(self):
        """Returns C type"""
        raise NotImplementedError()

    def get_cvalue(self):
        """Returns C variable value"""
        raise NotImplementedError()

    def get_struct_member_value(self):
        """Returns value of struct"""
        return self.get_cvalue()

    def get_desc(self):
        """Returns description of Option"""
        desc = '%s %s:' % (self.__class__.__name__,
                           self.name)
        if hasattr(self, 'value'):
            desc += '\nvaluetype=%s,\n value=%s' % (self.value.__class__.__name__,
                                                    repr(self.value))
        return desc

    def assrt(self, value, msg):
        """Asserts that msg is true"""
        assert_parse(value, '<' + self.get_desc() + '>:\n' + msg)

    def get_elements(self):
        """Returns list of elements as pairs of the form (type, name)"""
        return [(self.get_ctype(), self.name)]

    def get_elements_value(self):
        """Returns list of elements as tuples of the form (type, name, value)"""
        return [(self.get_ctype(), self.name, self.get_struct_member_value())]


class BoolOption(Option):
    """Represents boolean config option"""

    def validate(self):
        self.assrt(isinstance(self.value, bool), 'Invalid Boolean value "%s"' %
                   repr(self.value))

    def add_config(self, info):
        if not self.value_has_been_set:
            return
        if self.is_top_level:
            info.add_macro_def(self.name.upper(), self.get_cvalue())

    def get_cvalue(self):
        return 'true' if self.value else 'false'

    def get_ctype(self):
        return 'int'


class PosIntOption(Option):
    """Represents positive integer config option"""

    def validate(self):
        if isinstance(self.value, float):
            self.value = long(self.value)
        self.assrt(isinstance(self.value, int) or isinstance(self.value, long),
                   'Must be integer or long')
        self.assrt(self.value > 0, 'Must be greater than 0')

    def add_config(self, info):
        if self.is_top_level:
            info.add_macro_def(self.name.upper(), self.get_cvalue())

    def get_cvalue(self):
        return str(self.value)

    def get_ctype(self):
        return 'int'


class StringOption(Option):
    """Represents string config option"""

    def validate(self):
        self.assrt(is_string(self.value), 'Value "%s" is not string' %
                   repr(self.value))

    def add_config(self, info):
        if self.is_top_level:
            info.add_macro_def(self.name.upper(), self.get_cvalue())

    def get_ctype(self):
        return 'const char *'

    def get_cvalue(self):
        return c_str_repr(self.value)


class WhitelistOption(StringOption):
    """Represents option where certain characters are whitelisted"""

    num_bytes = 0x100 / 8

    def get_ctype(self):
        return 'const char *'

    def get_cvalue(self):
        chars = []
        byte = 0
        for i in range(0x100):
            byte_idx = i % 8
            char = chr(i)
            if re.match(self.value, char):
                byte |= (1 << byte_idx)
            if byte_idx == 7:
                chars.append(byte)
                byte = 0

        return c_str_repr(struct.pack(WhitelistOption.num_bytes * 'B', *chars))


class StringArrOption(Option):
    """Represents array of strings config option"""

    def __init__(self, name, min_len=0, allowed_vals=None,
                 is_element_valid=None, is_top_level=False, default_value=None):
        if default_value is None:
            default_value = []
        Option.__init__(self, name, defaultValue=default_value)
        self.value = default_value
        self.allowed_vals = allowed_vals
        self.min_len = min_len
        self.is_element_valid = is_element_valid
        self.is_top_level = is_top_level

    def validate(self):
        self.assrt(is_list_of(self.value, is_string, self.min_len),
                   'Must be list')
        if self.allowed_vals is not None:
            self.assrt(set(self.value).issubset(self.allowed_vals),
                       'Elements must be in allowed set: %s' %
                       repr(self.allowed_vals))
        if self.is_element_valid is not None:
            for elem in self.value:
                self.assrt(self.is_element_valid(elem), 'Invalid element "%s"' %
                           repr(elem))

    def add_config(self, info):
        if self.is_top_level:
            info.add_var_def(StringArrInst(self.name, self.value))

    def get_ctype(self):
        return 'const char **'

    def get_cvalue(self):
        return '{%s}' % ', '.join([c_str_repr(x) for x in self.value])


class HTTPReqsOption(StringArrOption):
    """Represents a list of HTTP methods"""
    def get_struct_member_value(self):
        return ' | '.join(['HTTP_REQ_' + x for x in self.value])

    def get_ctype(self):
        return 'int'


class MultiOption(Option):
    """Represents option that contains child options"""

    def __init__(self, name, required_conf, optional_conf, is_top_level=False,
                 name_visit_order=None):
        self.name = name
        self.value = None
        self.json_input = None
        self.value_has_been_set = False
        self.required_conf = deepcopy(required_conf)
        self.optional_conf = deepcopy(optional_conf)
        self.required_name2conf = {x.name:x for x in self.required_conf}
        self.optional_name2conf = {x.name:x for x in self.optional_conf}
        for conf in self.required_conf.union(self.optional_conf):
            self.assrt(isinstance(conf, Option), "Must take Options")
        self._instance_name = None
        self.is_top_level = is_top_level

        if name_visit_order != None:
            self.assrt(isinstance(name_visit_order, list), "nameVisitOrder must be a list")
            opt_names = set((x.name for x in self.get_all_options()))
            fmt_args = sorted(name_visit_order), sorted(opt_names)
            self.assrt(set(name_visit_order) == opt_names,
                       "Elements nameVisitOrder do not match names of options\n" +
                       ("nameVisitOrder=%s, optionNames=%s" % fmt_args))
        self.name_visit_order = name_visit_order

    def get_all_options_sorted(self):
        """Returns list of all options sorted"""
        if self.name_visit_order is not None:
            n2c = self.get_name2conf()
            for name in self.name_visit_order:
                yield n2c[name]
        else:
            for opt in self.get_all_options():
                yield opt

    def get_required_options_sorted(self):
        """Returns list of required options sorted"""
        for opt in self.get_all_options_sorted():
            if opt in self.required_conf:
                yield opt

    def get_optional_options_sorted(self):
        """Returns list of optional options sorted"""
        for opt in self.get_all_options_sorted():
            if opt in self.optional_conf:
                yield opt

    def value_sorted(self, value):
        """Return values sorted"""
        for opt in self.get_all_options_sorted():
            if opt.name in value.keys():
                yield (opt.name, value[opt.name])

    def validate(self):
        """Validate options"""
        for opt in self.get_required_options_sorted():
            self.assrt(opt.value_has_been_set, 'Option %s has not been specified' %
                       opt.name)
            opt.validate()
        for opt in self.get_optional_options_sorted():
            if opt.value_has_been_set:
                opt.validate()

    def set_value(self, value):
        """Set value"""
        self.value = value
        self.value_has_been_set = True

        # Create mapping between option name and option object
        name2conf = self.get_name2conf()

        # Set option values
        for optname, optval in self.value_sorted(value):
            self.assrt(optname in name2conf, 'Unknown option "%s"' % optname)
            name2conf[optname].set_value(optval)

    def add_config(self, info):
        """Add config"""
        for option in self.get_all_options():
            option.add_config(info)

    def get_name2conf(self):
        """Get dict mapping names to config"""
        name2conf = self.required_name2conf.copy()
        name2conf.update(self.optional_name2conf)
        return name2conf

    def get_all_options(self):
        """Return set of all options"""
        return self.required_conf.union(self.optional_conf)

    def get_ctype(self):
        """Return C type"""
        return 'void *'

    def get_instance_name(self):
        """Return instance name"""
        if self._instance_name is None:
            raise Exception('Instance name has not been set')
        return self._instance_name

    def set_instance_name(self, name):
        """Return name of instance"""
        self._instance_name = name

    def get_struct_member_value(self):
        """Return value of struct member"""
        return self.get_instance_name()


class DefaultPageConfOption(MultiOption):
    """Represents MultiOption for the default page config"""
    def __init__(self, name, required_conf, optional_conf, param_option, is_top_level=False):
        MultiOption.__init__(self, name, required_conf, optional_conf, is_top_level)
        self.param_option = param_option

    def add_config(self, info):
        # Add structure definition

        default_page_conf_name = 'default_page_conf'
        # Add name
        name_opt = StringOption('name')
        name_opt.set_value(default_page_conf_name)
        self.required_conf.add(name_opt)

        # Set params
        self.param_option.set_instance_name('NULL')
        self.required_conf.add(self.param_option)

        opts = list(self.get_all_options())
        Option.sort_struct_element_list(opts)
        page_conf_struct = StructDef('page_conf', opts)
        info.add_struct_def(page_conf_struct)

        # Call children
        for option in self.get_all_options():
            option.add_config(info)

        # Add default structure instance
        inst = StructInst(self, 'page_conf', inst_name=default_page_conf_name)
        info.add_page_conf_struct(inst)


class NamedOptionSet(MultiOption):
    """
    Represents option that has child options such that each child has a unique
    name that maps to the set of child options.
    """

    def __init__(self, name, required_conf, optional_conf, default_conf=None, is_top_level=False):
        MultiOption.__init__(self, name, required_conf, optional_conf)
        self.suboptions = {}
        self.orig_form = deepcopy(self)
        self.is_top_level = is_top_level
        self.default_conf = default_conf

    def _update_with_defaults(self, page_conf):
        """Set default values based on Default page config"""
        default_opt_name2val = self.default_conf.get_name2conf()
        for opt in page_conf.get_all_options():
            if isinstance(opt, NamedOptionSet):  # params
                for val in opt.suboptions.values():
                    self._update_with_defaults(val)
            else:
                if opt.value_has_been_set:
                    continue
                else:
                    opt.set_value(default_opt_name2val[opt.name].value)

    def set_value(self, value):
        """Set value"""
        self.value = value
        self.value_has_been_set = True
        for path, conf in value.items():
            page_conf = MultiOption(self.name + '$' + path, self.required_conf,
                                    self.optional_conf)
            page_conf.set_value(conf.copy())
            self.suboptions[path] = page_conf
            if self.default_conf != None:
                self._update_with_defaults(page_conf)

    def get_orig_form(self):
        """Get copy of original form"""
        return deepcopy(self.orig_form)

    def get_elements(self):
        """Get a list of all elements"""
        return [(self.get_ctype() + ' *', self.name),
                ('unsigned int', self.name + '_len')]

    def get_elements_value(self):
        """Get list of elements, including their values"""
        return [(self.get_ctype() + ' *', self.name, self.get_struct_member_value()),
                ('unsigned int', self.name + '_len', len(self.suboptions))]


class PageConfOption(NamedOptionSet):
    """Represents config for a specific page"""
    def validate(self):
        """Validates page config"""
        for path, page_conf in self.suboptions.items():
            self.assrt(is_page(path),
                       'Path "%s" is not valid, must start with a "/"' % path)
            page_conf.validate()

    def add_config(self, info):
        """Add config to page"""
        # Add structure definition
        name_opt = StringOption('name')
        self.required_conf.add(name_opt)
        opts = list(self.get_all_options())
        Option.sort_struct_element_list(opts)
        page_conf_struct = StructDef('page_conf', opts)
        info.add_struct_def(page_conf_struct)

        # Call children
        for option in self.get_all_options():
            option.add_config(info)

        # Add structure instances
        struct_insts = []
        for (page, options) in self.suboptions.items():
            for opt in options.get_all_options():
                opt.add_config(info)
            name_opt_copy = deepcopy(name_opt)
            name_opt_copy.set_value(page)
            options.required_conf.add(name_opt_copy)
            inst = StructInst(options, 'page_conf')
            struct_insts.append(inst)
            info.add_page_conf_struct(inst)

        page_conf_arr = StructArrInst(struct_insts, 'page_conf')
        page_conf_arr.name = 'pages_conf'
        info.add_page_conf_array(page_conf_arr)

    def get_ctype(self):
        """Returns C type"""
        return 'struct page_conf'


class ParamsOption(NamedOptionSet):
    """Represents options for HTTP parameters"""
    def validate(self):
        """Validates HTTP parameter options"""
        for param, param_conf in self.suboptions.items():
            self.assrt(is_string(param),
                       'Param "%s" is not valid, must be string' % param)
            self.assrt(not '%' in param, ('Param "%s" is not valid, must not ' % param) +
                       'contain any percent ("%") signs. Do not URL encode the parameters.')
            param_conf.validate()

    def add_config(self, info):
        """Adds config for param"""
        # Add structure definition
        name_opt = StringOption('name')
        self.required_conf.add(name_opt)
        opts = list(self.get_all_options())
        Option.sort_struct_element_list(opts)
        params_struct = StructDef('params', opts)
        info.add_struct_def(params_struct)

        # Call children
        for option in self.get_all_options():
            option.add_config(info)

        # Add structure instances
        struct_insts = []
        for (param, options) in self.suboptions.items():
            name_opt_copy = deepcopy(name_opt)
            name_opt_copy.set_value(param)
            options.required_conf.add(name_opt_copy)
            inst = StructInst(options, 'params')
            struct_insts.append(inst)
            info.add_params_struct(inst)

        params_arr = StructArrInst(struct_insts, 'params')
        info.add_params_array(params_arr)
        self.set_instance_name(params_arr.name)

    def get_ctype(self):
        return 'struct params'


def get_toplevel_conf():
    """Returns toplevel config"""
    # Configuration specification
    param_conf_required = set()
    param_conf_optional = {
        PosIntOption('max_param_len'),
        WhitelistOption('whitelist')
    }

    params_option = ParamsOption('params', param_conf_required, param_conf_optional)
    page_conf_required = set()
    allowed_http_req = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE',
                        'CONNECT', 'TRACE', 'OPTIONS']
    page_conf_optional = {
        params_option,
        BoolOption('restrict_params'),
        HTTPReqsOption('request_types', min_len=1,
                       allowed_vals=allowed_http_req),
        BoolOption('requires_login'),
        BoolOption('has_csrf_form'),
        BoolOption('receives_csrf_form_action')
    }.union(deepcopy(param_conf_optional))

    default_page_conf_required = {deepcopy(x) for x in page_conf_required.union(page_conf_optional)
                                  if x.name not in ['params']}
    default_page_conf_optional = set()

    # Update ENABLE_PARAM_CHECKS to depend on parameter options
    enable_options = {
        BoolOption('enable_header_field_len_check', is_top_level=True),
        BoolOption('enable_header_value_len_check', is_top_level=True),
        BoolOption('enable_request_type_check', is_top_level=True),
        BoolOption('enable_param_len_check', is_top_level=True),
        BoolOption('enable_param_whitelist_check', is_top_level=True),
        BoolOption('enable_url_directory_traversal_check', is_top_level=True),
        BoolOption('enable_csrf_protection', is_top_level=True),
        BoolOption('enable_https', is_top_level=True)
    }

    global_conf_required = {
        PosIntOption('max_header_field_len', is_top_level=True),
        PosIntOption('max_header_value_len', is_top_level=True)
    }.union(enable_options)

    global_conf_optional = {
        StringOption('https_certificate', is_top_level=True, defaultValue=""),
        StringOption('https_private_key', is_top_level=True, defaultValue=""),
        #StringArrOption('successful_login_pages', min_len=1, is_top_level=True, defaultValue=[]),
        PosIntOption('max_num_sessions', is_top_level=True, defaultValue=20),
        PosIntOption('session_life_seconds', is_top_level=True, defaultValue=300)
    }

    default_page_conf = DefaultPageConfOption(
        'default_page_config',
        default_page_conf_required,
        default_page_conf_optional,
        params_option)

    toplevel_conf = MultiOption('toplevel', {
        MultiOption('global_config', global_conf_required,
                    global_conf_optional),
        default_page_conf,
        PageConfOption('page_config', page_conf_required, page_conf_optional,
                       default_conf=default_page_conf)
        }, set(), name_visit_order=['default_page_config', 'global_config', 'page_config'])

    return toplevel_conf


def comments_removed_read(file_obj):
    """Given file object opened for reading, returns lines that are not comments"""
    ret_lines = []
    for line in file_obj.readlines():
        if not re.match(r"\s*#", line):
            ret_lines.append(line)
    return ''.join(ret_lines)

def parse_config(config_filename):
    """Parse config file and return populated toplevel config"""
    print 'Parsing config file "%s"' % config_filename
    toplevel_conf = get_toplevel_conf()
    with open(config_filename, 'r') as config_file:
        conf_str = comments_removed_read(config_file)
        conf = json.loads(conf_str)
        toplevel_conf.set_value(conf)
    toplevel_conf.validate()
    return toplevel_conf


def write_header(toplevel_conf, output_header_filename, output_body_filename):
    """Write populated toplevel config to output header and source files"""
    info = CodeHeader()
    toplevel_conf.add_config(info)
    with open(output_header_filename, 'w') as output_header_file:
        info.write_config_header(output_header_file)
    with open(output_body_filename, 'w') as output_body_file:
        info.write_config_body(output_header_filename, output_body_file)


def main():
    """Main driver function"""
    if len(sys.argv) != 4:
        print 'Usage: %s CONFIG OUTPUT_HEADER OUPUT_C_FILE' % sys.argv[0]
        sys.exit(1)
    config_file, output_header, output_body = tuple(sys.argv[1:])
    try:
        toplevel_conf = parse_config(config_file)
        write_header(toplevel_conf, output_header, output_body)
    except:
        if os.path.exists(output_header):
            os.remove(output_header)
        raise
    print '[done]'


if __name__ == '__main__':
    main()
