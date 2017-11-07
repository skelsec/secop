import sys
from pathlib import Path
import platform

###### PATH SETTINGS
current_path = Path(__file__)
basedir = Path(str(current_path.parents[1]))

###### PLATFORM SETTINGS
PLATFORM_OS = platform.system()

###### DB CONFIG
sqlite_file = str(basedir.joinpath('data').joinpath('scans.sqlite'))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + sqlite_file.replace('\\','\\\\')
SQLALCHEMY_TRACK_MODIFICATIONS = False


###### SCANNER CONFIG
MASSCAN_LOCATION = str(basedir.joinpath('bins').joinpath('masscan').joinpath('masscan.exe'))
NMAP_LOCATION = str(basedir.joinpath('bins').joinpath('nmap-7.60').joinpath('nmap.exe'))


###### LOGGING CONFIG
LOGLEVEL = 'DEBUG'
