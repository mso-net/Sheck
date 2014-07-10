import os
SECRET_KEY = "ENTERYOURSECRETKEYHERE"
MAIL_SERVER = "your.mailserver.local"
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_DEFAULT_SENDER = "webmaster@sheck"
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_DEBUG = True
MAIL_FAIL_SILENTLY = False
DEBUG = True
#DATABASE = {
#    'name': 'ssh_check_peewee.db',
#    'engine': 'peewee.SqliteDatabase',
#    'threadlocals': True
#}
DATABASE = {
	"name": "sheck",
	"engine": "peewee.MySQLDatabase",
	"user": "root",
	"passwd": "",
	"threadlocals": True
}