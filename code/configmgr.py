import configparser
import logging


class ConfigMgr:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read("config.ini")

    def getValue(self, section, key, default=None):
        logging.info("Trying to load config setting '" + str(key) + "' ...")
        try:
            val = self.config.get(section, key)
            logging.info("Success: " + str(val))
            return val
        except:
            logging.error("Failure!")
            return default

    def getIntValue(self, section, key, default=0):
        logging.info("Trying to load config setting '" + str(key) + "' ...")
        try:
            val = self.config.getint(section, key)
            logging.info("Success: " + str(val))
            return val
        except:
            logging.error("Failure!")
            return default

    def getBoolValue(self, section, key, default=False):
        logging.info("Trying to load config setting '" + str(key) + "' ...")
        try:
            val = self.config.getboolean(section, key)
            logging.info("Success: " + str(val))
            return val
        except:
            logging.error("Failure!")
            return default
