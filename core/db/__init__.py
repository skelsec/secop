import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from pathlib import Path, PurePath
import logging
import logging.handlers

current_path = PurePath(__file__)
basedir = PurePath(str(current_path.parents[2]))

app = Flask(__name__)
app.config.from_pyfile(str(basedir.joinpath('config').joinpath('config.py')))

if app.config['PLATFORM_OS'] == 'Windows':
	#not logging to windows log, because it's a mess
	handler = logging.StreamHandler(stream=sys.stdout)
else:
	handler = logging.handlers.SysLogHandler(address = '/dev/log')
formatter = logging.Formatter('%(module)s.%(funcName)s: %(message)s')
handler.setFormatter(formatter)


if app.config['LOGLEVEL'] == 'DEBUG' or app.debug:
	handler.setLevel(logging.DEBUG)
	app.logger.setLevel(logging.DEBUG)
elif app.config['LOGLEVEL'] == 'INFO':
	handler.setLevel(logging.INFO)
	app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)


db = SQLAlchemy(app)