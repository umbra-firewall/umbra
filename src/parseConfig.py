#!/usr/bin/python

import json
import sys

class ConfigValidationException(Exception):
    pass

def assertParse(value, msg):
    if not value:
        raise ConfigValidationException(msg)

def validateCorrectKeys(conf, required, optional = set()):
    requiredSet, optionalSet = set(required), set(optional)
    if not requiredSet.isdisjoint(optionalSet):
        raise Exception("Required and Optional sets must not intersect")
    allKeys = requiredSet.union(optionalSet)
    missingReqKeys = requiredSet.copy()
    
    for k in conf.keys():
        assertParse(k in allKeys, "Unknown element '%s'" % k)
        if k in requiredSet:
            missingReqKeys.discard(k)
    
    assertParse(len(missingReqKeys) == 0,
            "Configuration does not have required elments %s" %
            missingReqKeys)
    

def validateGlobalConf(conf):
    validateCorrectKeys(conf, {"https_certificate", "https_private_key",
                               "successful_login_pages"})
    assertParse(isString(conf["https_certificate"]),
                "HTTPS Certificate must be a string.")
    assertParse(isString(conf["https_private_key"]),
                "HTTPS Key must be a string.")
    assertParse(isListOf(conf["successful_login_pages"], isPage, minLen = 1),
                "Successful login pages must be a list of pages.")

def validatePageConf(conf):
    validateCorrectKeys(conf, {}, optional)

def isString(s):
    return type(s) is unicode or type(s) is str

def isPage(s):
    return isString(s) and len(s) > 0 and s[0] == '/'

def isListOf(x, typeFunc, minLen = 0):
    if type(x) is not list:
        return False
    return (reduce(lambda a,b: a and typeFunc(b), x, True)
            and minLen <= len(x))

def parseConfig(configFile, outputHeader):
    print 'Parsing config file', configFile
    f = open(configFile, 'r')
    conf = json.load(f)
    f.close()
    
    validateCorrectKeys(conf, {'page_config', 'global_config'})
    validateGlobalConf(conf['global_config'])
    validatePageConf(conf['page_config'])
    
def main():
    if len(sys.argv) != 3:
        print 'Usage: %s CONFIG OUTPUT_HEADER' % sys.argv[0]
        sys.exit(1)
    configFile, outputHeader = tuple(sys.argv[1:])
    parseConfig(configFile, outputHeader)

if __name__ == '__main__':
    main()
