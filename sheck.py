import paramiko,socket,StringIO,os,string,random,md5,pyotp,qrcode,time,datetime,json,pickle,re,wtforms
from datetime import timedelta
from PublicKey import PublicKey
from flask import Flask,render_template,request,redirect,url_for,send_file,flash
from flask.ext.mail import Mail,Message
from flask.ext.login import LoginManager,login_required,login_user,logout_user,current_user
from flask.ext.assets import Bundle, Environment
from htmlmin import minify
from threading import Thread
from flask_peewee.db import Database
from peewee import *
from functools import wraps,partial
from apscheduler.scheduler import Scheduler
from wtforms.ext.csrf.session import SessionSecureForm
from urlparse import urlparse

bundles = {
	"js": Bundle(
		"js/jquery.min.js",
		"js/bootstrap.min.js",
		"js/jquery.multi-select.js",
		"js/jquery.timeago.js",
		"js/jquery.peity.min.js",
		"js/parsley.min.js",
		output="gen/all.js",
		filters="jsmin"
	),
	"css": Bundle(
		"css/bootstrap-ubuntu.min.css",
		"css/base.css",
		"css/font-awesome.min.css",
		"css/multi-select.css",
		output="gen/all.css",
		filters="cssmin"
	)
}

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_pyfile("config.py", silent=True)
assets = Environment(app)
assets.register(bundles)

if "SENDGRID_USERNAME" in os.environ.keys() and "SENDGRID_PASSWORD" in os.environ.keys():
	#Sendgrid Heroku
	app.config["MAIL_SERVER"] = "smtp.sendgrid.net"
	app.config["MAIL_USERNAME"] = os.environ["SENDGRID_USERNAME"]
	app.config["MAIL_PASSWORD"] = os.environ["SENDGRID_PASSWORD"]
	app.config["MAIL_PORT"] = 587

mail = Mail(app)

if "CLEARDB_DATABASE_URL" in os.environ.keys():
	#MySQL Heroku
	db_url = urlparse(os.environ["CLEARDB_DATABASE_URL"])
	app.config["DATABASE"] = {
		"engine":"peewee.MySQLDatabase",
		"name":db_url.path[1:],
		"user":db_url.username,
		"passwd":db_url.password,
		"host":db_url.hostname,
		"port":int(db_url.port) if db_url.port is not None else 3306,
		"threadlocals": True
	}

db = Database(app)
login_manager = LoginManager()
login_manager.init_app(app)
sched = Scheduler()
sched.start()

class ParsleyForm(SessionSecureForm):
	SECRET_KEY = app.config["SECRET_KEY"]
	TIME_LIMIT = timedelta(minutes=20)

	def __init__(self, *args, **kwargs):
		default_number = -1
		super(ParsleyForm,self).__init__(**kwargs)
		for field in self._fields:
			self[field].validators_list = {}
			if len(self[field].validators)>0:
				self[field].validators_list["data-parsley-trigger"] = "change"

			for validator in self[field].validators:
				vtype = type(validator)
				if vtype is wtforms.validators.Length:
					if validator.max != default_number and validator.min != default_number:
						self[field].validators_list["data-parsley-length"] = "[%s,%s]"%(validator.min,validator.max)
					else:
						if validator.max == default_number:
							self[field].validators_list["data-parsley-minlength"] = str(validator.min)
						if validator.min == default_number:
							self[field].validators_list["data-parsley-maxlength"] = str(validator.max)
				elif (vtype is wtforms.validators.Required or vtype is wtforms.validators.InputRequired):
					self[field].validators_list["data-parsley-required"] = "true"
				elif vtype is wtforms.validators.Email:
					self[field].validators_list["data-parsley-type"] = "email"
				elif vtype is wtforms.validators.EqualTo:
					self[field].validators_list["data-parsley-equalto"] = "#%s"%validator.fieldname
				elif vtype is wtforms.validators.IPAddress:
					self[field].validators_list["data-parsley-pattern"] =\
						r'^\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
						r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
						r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
						r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$'
					self[field].validators_list["data-parsley-trigger"] += " key"
				elif vtype is wtforms.validators.NumberRange:
					self[field].validators_list["data-parsley-range"] = "[%s,%s]"%(validator.min,validator.max)
				elif vtype is wtforms.validators.Regexp:
					RegexObject = type(re.compile(""))
					if isinstance(validator.regex, RegexObject):
						regex_string = validator.regex.pattern
					else:
						regex_string = validator.regex
					self[field].validators_list["data-parsley-pattern"] = regex_string
				elif vtype is wtforms.validators.URL:
					self[field].validators_list["data-parsley-type"] = "url"
				if validator.message is not None:
					self[field].validators_list["data-parsley-error-message"] = validator.message

def executeCommand(orc_id,passphrase="",addLogEntry=True):
	with app.app_context():
		s = get_config("management_key")
		try:
			keyfile = StringIO.StringIO(s)
			mykey = paramiko.DSSKey.from_private_key(keyfile,passphrase)
		except:
			try:
				keyfile = StringIO.StringIO(s)
				mykey = paramiko.RSAKey.from_private_key(keyfile,passphrase)
			except:
				raise
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		servers = Server.select()
		orc = ORC.select().where(ORC.id == orc_id).get()
		resultSet = []
		for server in servers:
			curServer = {"id":server.id,"users":[]}
			users = User.select().where(User.server == server)
			for user in users:
				curUser = {"id":user.id,"result":""}
				ssh.connect(server.ip,username=user.user,pkey=mykey,timeout=5,port=server.port)
				sshstdin,sshstdout,sshstderr=ssh.exec_command(orc.command)

				curUser["result"] = "".join(sshstdout.readlines()).strip()
				curServer["users"].append(curUser)
			resultSet.append(curServer)
		for server in resultSet:
			for user in server["users"]:
				ORCResult.insert(server=server["id"],user=user["id"],orc=orc.id,response=user["result"]).execute()
		ORC.update(last_run=datetime.datetime.now()).where(ORC.id == orc.id).execute()
		if addLogEntry:
			add_log("Finished executing ORC %s"%orc.id)


def checkServers(passphrase=""):
	with app.app_context():
		returnString = ""

		s = get_config("management_key")
		try:
			keyfile = StringIO.StringIO(s)
			mykey = paramiko.DSSKey.from_private_key(keyfile,passphrase)
		except:
			try:
				keyfile = StringIO.StringIO(s)
				mykey = paramiko.RSAKey.from_private_key(keyfile,passphrase)
			except:
				raise
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		servers = Server.select()
		
		keys_to_insert={}
		for server in servers:
			try:
				#connect to target server and cat specified authorized_keys file
				users = User.select().where(User.server == server)
				for user in users:
					ssh.connect(server.ip,username=user.user,pkey=mykey,timeout=5,port=server.port)
					sshstdin,sshstdout,sshstderr=ssh.exec_command("cat %s"%user.auth_file_location)
					#serverKeys = []

					#loop over authorized_keys file content and extract key aliases
					for keyLine in sshstdout.readlines():
						if not keyLine.startswith("#") and keyLine.strip() != "":
							curKey = keyLine.strip()
							try:
								curKeyObj = PublicKey(curKey)
								if len(curKeyObj.comment.strip())>0:
									curKeyFingerprint = str(curKeyObj.fingerprint(hex=True))
									key_exists = ((Key.select(Key, fn.Count(Key.id).alias("count")).where(Key.fingerprint == curKeyFingerprint)).get().count==1) and (curKeyFingerprint not in keys_to_insert)

									try:
										if not key_exists:
											keys_to_insert[curKeyFingerprint] = {
												"comment":curKeyObj.comment.strip(),
												"algo":curKeyObj.algo.strip(),
												"blob":curKeyObj.blob.encode("base64").strip(),
												"prefix":curKeyObj.prefix.strip(),
												"fingerprint":curKeyFingerprint
											}
									except:
										add_log("Key insert error")
							except ValueError:
								pass
					#clean up after ourselves
					ssh.close()
			#handle socket timeout exception
			except socket.timeout:
				print "[ERROR] Timeout %s (%s)"%(server.alias,server.ip)
				pass
			#handle authentication exception
			except paramiko.AuthenticationException:
				print "[ERROR] Authentication Failure %s (%s)"%(server.alias,server.ip)
				pass

		for fingerprint,key in keys_to_insert.items():
			Key.insert(comment=key["comment"],algo=key["algo"],blob=key["blob"],prefix=key["prefix"],fingerprint=key["fingerprint"]).execute()
		add_log("Rescan completed")
	return returnString

def dict_factory(cursor, row):
	d = {}
	for idx, col in enumerate(cursor.description):
		d[col[0]] = row[idx]
	return d

def full_minify(data):
	return_data = minify(data,remove_empty_space=True,reduce_boolean_attributes=True,remove_optional_attribute_quotes=True,keep_pre=True).replace("\t","")
	return re.sub("(?!<pre[^>]*?>)\n(?![^<]*?</pre>)","",return_data)

def id_generator(size=8, chars=string.ascii_lowercase + string.ascii_uppercase + string.digits):
	return "".join(random.choice(chars) for _ in range(size))

def md5_hash(input):
	m = md5.new()
	m.update(input)
	return m.hexdigest()

def add_log(data):
	with app.app_context():
		Log.insert(data=data).execute()

def send_email(subject, recipients, text_body, html_body,attachments=[]):
	msg = Message(subject=subject, recipients = recipients)
	msg.body = text_body
	msg.html = html_body
	for filename,filedata,filetype in attachments:
		msg.attach(filename=filename,data=filedata,content_type=filetype,headers=[("Content-ID","<%s>"%filename)])
	mail.send(msg)

def serve_pil_image(pil_img):
	img_io = StringIO.StringIO()
	pil_img.save(img_io, 'PNG')
	img_io.seek(0)
	return send_file(img_io, mimetype='image/png')

def is_number(s):
	try:
		float(s)
	except ValueError:
		try:
			complex(s)
		except ValueError:
			return False

	return True

def check_private_key_valid(privateKey,passphrase=""):
	try:
		keyfile = StringIO.StringIO(privateKey)
		paramiko.DSSKey.from_private_key(keyfile,passphrase)
		return True
	except:
		try:
			keyfile = StringIO.StringIO(privateKey)
			paramiko.RSAKey.from_private_key(keyfile,passphrase)
			return True
		except:
			return False
	return False

def get_keystring_from_privkey(privateKey,passphrase=""):
	s = privateKey
	try:
		keyfile = StringIO.StringIO(s)
		return "ssh-dss %s sheck"%(paramiko.DSSKey.from_private_key(keyfile,passphrase).get_base64())
	except:
		try:
			keyfile = StringIO.StringIO(s)
			return "ssh-rsa %s sheck"%(paramiko.RSAKey.from_private_key(keyfile,passphrase).get_base64())
		except:
			raise
	return None

@login_manager.user_loader
def load_user(user_id):
	return Person.select().where(Person.id == user_id).first()

def check_is_installed():
	return Person.select().count()>0

def requires_management(func=None):
	@wraps(func)
	def decorated_view(*args, **kwargs):
		if app.login_manager._login_disabled:
			return func(*args, **kwargs)
		else:
			passphrase = request.form.get("passphrase",None)
			otp = request.form.get("otp",None)
			if ((passphrase is None and not get_config("store_passphrase")) or (otp is None and get_config("use_utop"))):
				if request.headers.get("X-Requested-With") == "XMLHttpRequest":
					return json.dumps({"result":"pom"})
				else:
					return full_minify(render_template("requires_management.html",url=request.path,invalid_creds=False))
			else:
				if get_config("use_otp"):
					secret = current_user.secret
					otp_now = pyotp.TOTP(secret).now()
					otp_valid = str(otp_now)==str(otp)
				else:
					otp_valid = True

				if get_config("store_passphrase"):
					passphrase = get_config("passphrase")


				if otp_valid:
					passphrase_valid = check_private_key_valid(get_config("management_key"),passphrase)
					if passphrase_valid:
						return func(*args, **kwargs)
					else:
						if request.headers.get("X-Requested-With") == "XMLHttpRequest":
							return json.dumps({"result":"denied"}),401
						else:
							return full_minify(render_template("requires_management.html",url=request.path,invalid_creds=True))
				else:
					if request.headers.get("X-Requested-With") == "XMLHttpRequest":
						if otp is None:
							return json.dumps({"result":"pom"})
						else:
							return json.dumps({"result":"denied"}),401
					else:
						if otp is None:
							return full_minify(render_template("requires_management.html",url=request.path))
						else:
							return full_minify(render_template("requires_management.html",url=request.path,invalid_creds=True))
	return decorated_view

def is_installed(func=None):
	@wraps(func)
	def decorated_view(*args, **kwargs):
		if app.login_manager._login_disabled:
			return func(*args, **kwargs)
		else:
			if check_is_installed():
				return func(*args, **kwargs)
			else:
				return app.login_manager.unauthorized()
	return decorated_view

# OR compare, must have at least one ability
def has_ability(func=None,ability=[]):
	if not callable(func):
		return partial(has_ability,ability=func)
	func.gw_method = string or method.__name__

	@wraps(func)
	def decorated_view(*args, **kwargs):
		if app.login_manager._login_disabled:
			return func(*args, **kwargs)
		else:
			if type(ability) is list:
				if len(ability)==0:
					return func(*args, **kwargs)
				else:
					if current_user.is_anonymous():
						return app.login_manager.unauthorized()
					else:
						for ability_ in ability:
							if current_user.has_ability(ability_):
								return func(*args, **kwargs)
						return app.login_manager.unauthorized()
			else:
				if ability == "":
					return func(*args, **kwargs)
				else:
					if current_user.is_anonymous():
						return app.login_manager.unauthorized()
					else:
						if not current_user.has_ability(ability):
							return app.login_manager.unauthorized()
			return func(*args, **kwargs)
	return decorated_view


def bool_config(func=None,config_key=None):
	if not callable(func):
		return partial(bool_config,config_key=func)
	func.gw_method = string or method.__name__

	@wraps(func)
	def decorated_view(*args, **kwargs):
		config_value = get_config(config_key,False)
		if isinstance(config_value,bool):
			if config_value:
				return func(*args, **kwargs)
			else:
				return app.login_manager.unauthorized()
		else:
			return app.login_manager.unauthorized()
	return decorated_view

# AND compare, must have all ablities
def has_abilities(func=None,ability_list=[]):
	if not callable(func):
		return partial(has_abilities,ability_list=func)
	func.gw_method = string or method.__name__

	@wraps(func)
	def decorated_view(*args, **kwargs):
		if app.login_manager._login_disabled:
			return func(*args, **kwargs)
		else:
			if type(ability_list) == "list":
				if len(ability_list) == 0:
					return func(*args, **kwargs)
				else:
					if current_user.is_anonymous():
						return app.login_manager.unauthorized()
					else:
						for ability in ability_list:
							if not current_user.has_ability(ability):
								return app.login_manager.unauthorized()
						return func(*args, **kwargs)
			else:
				return app.login_manager.unauthorized()
	return decorated_view

def anonymous_required(func=None):
	@wraps(func)
	def decorated_view(*args, **kwargs):
		if app.login_manager._login_disabled:
			return func(*args, **kwargs)
		else:
			if current_user.is_anonymous():
				return func(*args, **kwargs)
			else:
				return app.login_manager.unauthorized()
	return decorated_view

def write_remote_file(server_id,user_id,contents,passphrase):
	server = Server.select().where(Server.id==server_id).get()
	user = server.users.select().where(User.id==user_id).get()

	s = get_config("management_key")
	try:
		keyfile = StringIO.StringIO(s)
		mykey = paramiko.DSSKey.from_private_key(keyfile,passphrase)
	except:
		try:
			keyfile = StringIO.StringIO(s)
			mykey = paramiko.RSAKey.from_private_key(keyfile,passphrase)
		except:
			raise

	transport = paramiko.Transport((server.ip,server.port))

	transport.connect(username=user.user, pkey=mykey)
	sftp = paramiko.SFTPClient.from_transport(transport)
	sftp.chdir(".")

	file_path = ("%s"%(user.auth_file_location)).replace("~",sftp.getcwd(),1)
	f = sftp.open(file_path,"wb")
	f.write(contents)
	f.close()

def generate_write(server_id,passphrase):
	key_data = []

	server = Server.select().where(Server.id==server_id).get()
	cur_server = {"alias":server.alias,"ip":server.ip,"port":server.port,"users":[]}
	server_users = User.select().where(User.server == server.id).order_by(User.user.asc())
	for server_user in server_users:
		cur_user = {"user":server_user.user,"id":server_user.id,"password":server_user.password,"auth_file_location":server_user.auth_file_location,"keys":[]}
		user_people = Person.select().join(PeopleUsers).where(PeopleUsers.user == server_user)
		for user_person in user_people:
			person_keys = Key.select().join(PeopleKeys).where(PeopleKeys.person == user_person)
			for person_key in person_keys:
				cur_key = {"blob":person_key.blob,"algo":person_key.algo,"prefix":"" if person_key.prefix is None else person_key.prefix,"person":user_person.email}
				cur_user["keys"].append(cur_key)
		cur_server["users"].append(cur_user)

	for cur_user in cur_server["users"]:
		auth_file_output = "# Sheck management key\n%s\n"%get_config("management_key_public").replace("\n","")
		for cur_key in cur_user["keys"]:
			auth_file_output = "%s\n# %s\n%s%s %s %s"%(auth_file_output,cur_key["person"],"%s "%(cur_key["prefix"]) if cur_key["prefix"] is not u"" else "",cur_key["algo"],cur_key["blob"].replace("\n",""),cur_key["person"])

		write_remote_file(server_id,cur_user["id"],auth_file_output,passphrase)
	key_data.append(cur_server)

def generate_all(passphrase):
	with app.app_context():
		servers = Server.select()
		for server in servers:
			generate_write(server.id,passphrase)
		add_log("Finished generate")

@app.route("/rescan",methods=["GET","POST"])
@has_ability("RESCAN")
@requires_management
def rescan_servers(passphrase=""):
	add_log("Started rescan")
	thread = Thread(target = checkServers, args = [request.form.get("passphrase") if not get_config("store_passphrase") else get_config("passphrase")])
	thread.start()
	return json.dumps({"result":"ok"})

@app.route("/servers")
@login_required
@has_ability(["ADD_SERVER","EDIT_SERVER","DELETE_SERVER","ADD_USER","DELETE_USER","REQUEST_SERVER_ACCESS","GRANT_SERVER_ACCESS"])
def server_list():
	server_data = Server.select(Server,fn.Count(AccessRequest.id).alias("requestcount"),fn.Count(User.id).alias("usercount"),fn.Count(PeopleUsers.id).alias("accesscount")).join(User,on=User.server==Server.id,join_type=JOIN_LEFT_OUTER).join(PeopleUsers,on=PeopleUsers.user==User.id,join_type=JOIN_LEFT_OUTER).join(AccessRequest,on=((AccessRequest.user==User.id) & (AccessRequest.granted==0)),join_type=JOIN_LEFT_OUTER).group_by(Server.id).order_by(Server.alias.asc())
	return full_minify(render_template("server/list.html",servers=server_data))

class ServerAddForm(ParsleyForm):
	alias = wtforms.StringField("Alias",[wtforms.validators.Regexp(re.compile("[a-zA-Z0-9]"),message="Alpha numerics only please")])
	ip = wtforms.StringField("IP Address",[wtforms.validators.IPAddress(message="This must be a valid IP Address"),wtforms.validators.Required(message="This field is required")])
	port = wtforms.StringField("Port",default=22)

@app.route("/server/add",methods=["GET","POST"])
@has_ability("ADD_SERVER")
def server_add():
	form = ServerAddForm(csrf_context=current_user.session)

	if request.method == "POST":
		form.process(request.form)

		if form.validate():
			Server.insert(ip=form.ip.data,port=form.port.data,alias=form.alias.data).execute()
			add_log("Added server %s:%s - %s"%(form.ip.data,form.port.data,form.alias.data))
			return redirect(url_for("server_list"))

	return full_minify(render_template("server/add.html",form=form))

@app.route("/server/<server_id>/edit",methods=["GET","POST"])
@has_ability("EDIT_SERVER")
def server_edit(server_id):
	try:
		server = Server.get(Server.id==server_id)
		form = ServerAddForm(csrf_context=current_user.session)
		if request.method == "POST":
			form.process(request.form)
			if form.validate():
				server.alias = form.alias.data
				server.ip = form.ip.data
				server.port = form.port.data
				server.save()
				add_log("Edited server %s"%server_id)
			else:
				return full_minify(render_template("server/add.html",server_id=server_id,form=form))
		else:
			form.process(**server._data)
			return full_minify(render_template("server/add.html",server_id=server_id,form=form))
	except Server.DoesNotExist:
		flash("Invalid server","danger")
	return redirect(url_for("server_list"))

@app.route("/server/<server_id>/delete")
@has_ability("DELETE_SERVER")
def server_delete(server_id):
	try:
		server = Server.get(Server.id==server_id)
		for user in Server.select().where(Server.id == server_id).first().users:
			PeopleUsers.delete().where(PeopleUsers.user == user.id).execute()
			ORCResult.delete().where(ORCResult.user == user.id).execute()
			AccessRequest.delete().where(AccessRequest.user == user.id).execute()
			User.delete().where(User.id == user.id).execute()
		server.delete_instance()
		add_log("Deleted server %s"%(server_id))
	except Server.DoesNotExist:
		flash("Invalid server","danger")

	return redirect(url_for("server_list"))

@app.route("/server/<server_id>/users")
@has_ability(["ADD_USER","EDIT_USER","DELETE_USER"])
def server_user_list(server_id):
	return full_minify(render_template("server/user/list.html",users=User.select().join(Server).where(Server.id == server_id)))	

class ServerUserAddForm(ParsleyForm):
	user = wtforms.StringField("Username")
	password = wtforms.StringField("Password")
	auth_file_location = wtforms.StringField("Auth File Location",default="~/.ssh/authorized_keys")

@app.route("/server/<server_id>/user/add",methods=["GET","POST"])
@has_ability("ADD_USER")
def server_user_add_(server_id):
	try:
		Server.get(Server.id==server_id)
		form = ServerUserAddForm(csrf_context=current_user.session)
		
		if request.method == "POST":
			form.process(request.form)
			if form.validate():
				try:
					User.get(User.server==server_id,User.user==form.user.data)
					add_log("User already exists","danger")
					return full_minify(render_template("server/user/add.html",server_id=server_id,form=form))
				except User.DoesNotExist:
					User.insert(user=form.user.data,password=form.password.data,auth_file_location=form.auth_file_location.data,server=server_id).execute()
					add_log("Added user %s to server %s"%(form.user.data,server_id))
			else:
				return full_minify(render_template("server/user/add.html",server_id=server_id,form=form))
		else:
			return full_minify(render_template("server/user/add.html",server_id=server_id,form=form))
	except Server.DoesNotExist:
		flash("Invalid server","danger")
		return redirect(url_for("server_list"))
	return redirect(url_for("server_user_list",server_id=server_id))

@app.route("/server/<server_id>/user/<user_id>/edit",methods=["GET","POST"])
@has_ability("EDIT_USER")
def server_user_edit_form(server_id,user_id):
	try:
		user = User.get(User.server==server_id,User.id==user_id)
		form = ServerUserAddForm(csrf_context=current_user.session)

		if request.method == "POST":
			form.process(request.form)
			if form.validate():
				user.user = form.user.data
				user.password = form.password.data if form.password.data != "" else None
				user.auth_file_location = form.auth_file_location.data
				user.save()
				add_log("Edited user %s"%user_id)
				return redirect(url_for("server_user_list",server_id=server_id))
		else:
			form.process(**user._data)
		return full_minify(render_template("server/user/add.html",server_id=server_id,user=user,form=form))
	except User.DoesNotExist:
		flash("Invalid user","danger")
		return redirect(url_for("server_user_list",server_id=server_id))

@app.route("/server/<server_id>/user/<user_id>/delete")
@has_ability("DELETE_USER")
def server_user_delete(server_id,user_id):
	try:
		user = User.get(User.server==server_id,User.id==user_id)
		AccessRequest.delete().where(AccessRequest.user == user_id).execute()
		ORCResult.delete().where(ORCResult.user == user_id).execute()
		PeopleUsers.delete().where(PeopleUsers.user == user_id).execute()
		user.delete_instance()
		add_log("Deleted user %s from server %s"%(user_id,server_id))
	except User.DoesNotExist:
		flash("Invalid user","danger")
	return redirect(url_for("server_user_list",server_id=server_id))

class RequestAccessForm(ParsleyForm):
	users = wtforms.SelectMultipleField()

@app.route("/server/<server_id>/request",methods=["GET","POST"])
@has_ability("REQUEST_SERVER_ACCESS")
def server_request_access_form(server_id):
	form = RequestAccessForm(csrf_context=current_user.session)

	users = User.select().where(User.server==server_id).order_by(User.user)
	choices = [(str(user.id),str(user.user)) for user in users if user.requests.select().where(AccessRequest.person==current_user.id,AccessRequest.granted==0).count()==0]

	form.users.choices=choices

	if request.method == "POST":
		form.process(request.form)

		if form.validate():
			for user_id in form.users.data:
				has_pending_request = AccessRequest.select().where(AccessRequest.person==current_user.id,AccessRequest.granted==0,AccessRequest.user==user_id).count()>0
				has_access = PeopleUsers.select().where(PeopleUsers.person==current_user.id,PeopleUsers.user==user_id).count()>0
				if not has_pending_request and not has_access:
					AccessRequest.insert(person=current_user.id,user=user_id).execute()
					add_log("Person %s requesting access to User %s"%(current_user.id,user_id))
			return redirect(url_for("server_list"))
	return full_minify(render_template("server/request_access.html",server_id=server_id,form=form))

@app.route("/server/<server_id>/grant",methods=["GET"])
@has_ability("GRANT_SERVER_ACCESS")
def server_grant_access_form(server_id):
	return full_minify(render_template("server/grant_access.html",server_id=server_id,access_requests=AccessRequest.select(AccessRequest,Person,User).join(Person,on=AccessRequest.person==Person.id).join(User,on=User.id==AccessRequest.user).where(AccessRequest.granted==0).order_by(AccessRequest.time.desc())))

@app.route("/server/<server_id>/grant",methods=["POST"])
@has_ability("GRANT_SERVER_ACCESS")
def server_grant_access(server_id):
	request_id = request.form.get("request","")
	if request_id != "":
		access_request = AccessRequest.select().where(AccessRequest.id==request_id).first()
		AccessRequest.update(granted=1,time=datetime.datetime.now()).where(AccessRequest.id==request_id).execute()
		PeopleUsers.insert(person=access_request.person,user=access_request.user).execute()
		add_log("Granted access request for Person %s to User %s"%(access_request.person.id,access_request.user.id))
	return redirect("/server/%s/grant"%server_id)

@app.route("/server/<server_id>/deny",methods=["POST"])
@has_ability("GRANT_SERVER_ACCESS")
def server_deny_access(server_id):
	request_id = request.form.get("request","")
	if request_id != "":
		access_request = AccessRequest.select().where(AccessRequest.id==request_id).first()
		add_log("Denied access request for Person %s to User %s"%(access_request.person.id,access_request.user.id))
		AccessRequest.delete().where(AccessRequest.id==request_id).execute()
	return redirect("/server/%s/grant"%server_id)

@app.route("/people")
@has_ability(["ADD_PERSON","EDIT_PERSON","DELETE_PERSON","ASSIGN_KEY_TO_PERSON","ASSIGN_ACCESS_TO_PERSON","EDIT_PERSON_ABILITIES"])
def people_list():
	return full_minify(render_template("people/list.html",people=Person.select().order_by(Person.alias.asc())))

@app.route("/person/add",methods=["GET"])
@has_ability("ADD_PERSON")
def person_add_form():
	ability_categories = AbilityCategory.select(AbilityCategory,fn.Group_Concat(Ability.alias).alias("alias_list"),fn.Group_Concat(Ability.key).alias("key_list")).join(Ability).order_by(AbilityCategory.alias.asc(),Ability.alias.asc()).group_by(AbilityCategory.id)

	return full_minify(render_template("people/add.html",ability_categories=ability_categories))

@app.route("/person/add",methods=["POST"])
@has_ability("ADD_PERSON")
def person_add():
	alias = request.form.get("alias")
	email = request.form.get("email")
	if alias!="" and email!="":
		person_exists = Person.select(Person, fn.Count(Person.id).alias("count")).where(Person.email == email).get().count==1
		
		if person_exists:
			return "Dupicate person"
		else:
			password = id_generator()
			salt = md5_hash(id_generator())
			password_hash = md5_hash("%s%s"%(password,salt))
			person_id=Person.insert(alias=alias,email=email,password=password_hash,salt=salt).execute()
			if current_user.has_ability("EDIT_PERSON_ABILITIES"):
				abilities = request.form.getlist("abilities")
				for ability_key in abilities:
					PeopleAbilities.insert(person=person_id,ability=Ability.select().where(Ability.key==ability_key).first()).execute()

			add_log("Added person %s"%(email))

			send_email(
				"Welcome to Sheck",
				[email],
				render_template("people/email_add.txt",alias=alias,password=password),
				render_template("people/email_add.html",alias=alias,password=password)
			)
	return redirect(url_for("people_list"))

@app.route("/person/<person_id>/edit",methods=["GET"])
@has_ability(["EDIT_PERSON","EDIT_PERSON_ABILITIES"])
def person_edit_form(person_id):
	person = Person.select().where(Person.id==person_id)
	if person.count()==1:
		person = person.first()
		ability_categories = AbilityCategory.select(AbilityCategory,fn.Group_Concat(Ability.alias).alias("alias_list"),fn.Group_Concat(Ability.key).alias("key_list")).join(Ability).order_by(AbilityCategory.alias.asc(),Ability.alias.asc()).group_by(AbilityCategory.id)
		person_abilities = Person.select(fn.Group_Concat(Ability.key).alias("key_list")).join(PeopleAbilities,JOIN_LEFT_OUTER).join(Ability,JOIN_LEFT_OUTER).where(Person.id==person_id).group_by(Person.id).first().key_list
		return full_minify(render_template("people/add.html",ability_categories=ability_categories,person=person,person_abilities=person_abilities))
	else:
		flash("Invalid person","danger")
		return redirect(url_for("people_list"))

@app.route("/person/<person_id>/edit",methods=["POST"])
@has_ability(["EDIT_PERSON","EDIT_PERSON_ABILITIES"])
def person_edit(person_id):
	person = Person.select().where(Person.id==person_id)
	if person.count()==1:
		if current_user.has_ability("EDIT_PERSON"):
			#do edit person details
			Person.update(alias=request.form.get("alias"),email=request.form.get("email")).where(Person.id==person_id)
		if current_user.has_ability("EDIT_PERSON_ABILITIES"):
			#do edit person abilities
			abilities = request.form.getlist("abilities")
			PeopleAbilities.delete().where(PeopleAbilities.person == person_id).execute()
			for ability_key in abilities:
				PeopleAbilities.insert(person=person_id,ability=Ability.select().where(Ability.key==ability_key).first()).execute()
		add_log("Edited Person %s"%person_id)
	else:
		flash("Invalid person","danger")

	return redirect(url_for("people_list"))

class PeopleEditKeysForm(ParsleyForm):
	keys = wtforms.SelectMultipleField()

@app.route("/person/<person_id>/keys",methods=["GET","POST"])
@has_ability("ASSIGN_KEY_TO_PERSON")
def person_edit_keys(person_id):
	form = PeopleEditKeysForm(csrf_context=current_user.session)
	keys = Key.select(Key,PeopleKeys).join(PeopleKeys,JOIN_LEFT_OUTER).join(Person,JOIN_LEFT_OUTER).where((Person.id == None) | (Person.id == person_id)).order_by(Key.comment.asc())

	choices = [(str(key.id),key.comment) for key in keys]
	choices_selected = [str(key.id) for key in keys if not key.peoplekeys.id == None]
	form.keys.choices=choices

	if request.method == "POST":
		form.process(request.form)

		if form.validate():
			PeopleKeys.delete().where(PeopleKeys.person == person_id).execute()
			for key in form.keys.data:
				PeopleKeys.insert(person=person_id,key=key).execute()
			add_log("Updated keys for person %s"%(person_id))
			return redirect(url_for("people_list"))
	else:
		form.keys.data=choices_selected

	return full_minify(render_template("people/keys/edit.html",person_id=person_id,form=form))

@app.route("/person/<person_id>/access",methods=["GET"])
@has_ability("ASSIGN_ACCESS_TO_PERSON")
def person_edit_access_form(person_id):
	server_data = Server.select(Server,User,PeopleUsers,Person).join(User).join(PeopleUsers,JOIN_LEFT_OUTER).join(Person,JOIN_LEFT_OUTER).order_by(Server.alias.asc(),User.user.asc())
	return full_minify(render_template("people/access/edit.html",person_id=int(person_id),server_data=server_data))

@app.route("/person/<person_id>/access",methods=["POST"])
@has_ability("ASSIGN_ACCESS_TO_PERSON")
def person_edit_access(person_id):
	PeopleUsers.delete().where(PeopleUsers.person == person_id).execute()

	for field in request.form:
		if field.startswith("server["):
			access = request.form.getlist(field)
			for user_id in access:
				PeopleUsers.insert(person=person_id,user=user_id).execute()
	add_log("Updated access for person %s"%(person_id))
	return redirect(url_for("people_list"))

@app.route("/person/<person_id>/delete")
@has_ability("DELETE_PERSON")
def person_delete(person_id):
	person_exists = Person.select(Person, fn.Count(Person.id).alias("count")).where(Person.id == person_id).get().count==1

	if person_exists:
		PeopleKeys.delete().where(PeopleKeys.person == person_id).execute()
		PeopleUsers.delete().where(PeopleUsers.person == person_id).execute()
		PeopleAbilities.delete().where(PeopleAbilities.person == person_id).execute()
		Person.delete().where(Person.id == person_id).execute()
		add_log("Deleted person %s"%(person_id))

	return redirect(url_for("people_list"))

@app.route("/keys")
@has_ability("ADD_KEY")
def key_list():
	return full_minify(render_template("key/list.html",keys=Key.select(Key,PeopleKeys, fn.Count(PeopleKeys.id).alias("count")).join(PeopleKeys,JOIN_LEFT_OUTER).group_by(Key.id).order_by(Key.comment.asc())))

class KeyAddForm(ParsleyForm):
	keystring = wtforms.StringField("Public Key String")

@app.route("/key/add",methods=["GET","POST"])
@has_ability("ADD_KEY")
def key_add():
	form = KeyAddForm(csrf_context=current_user.session)
	if request.method == "POST":
		form.process(request.form)
		try:
			curKeyObj = PublicKey(form.keystring.data)
			curKeyFingerprint = curKeyObj.fingerprint(hex=True)
			try:
				Key.get(Key.fingerprint == curKeyFingerprint)
				flash("Key already exists","danger")
			except Key.DoesNotExist:
				Key.insert(comment=curKeyObj.comment.strip(),algo=curKeyObj.algo.strip(),blob=curKeyObj.blob.encode("base64").strip(),prefix=curKeyObj.prefix.strip(),fingerprint=curKeyFingerprint).execute()
				add_log("Added key %s"%(curKeyFingerprint))
				return redirect(url_for("key_list"))
		except:
			flash("Invalid key","danger")

	return full_minify(render_template("key/add.html",form=form))

@app.route("/generate_write",methods=["GET","POST"])
@has_ability("GENERATE_WRITE")
@requires_management
def generate_action():
	add_log("Started generate")
	thread = Thread(target=generate_all,args = [request.form.get("passphrase") if not get_config("store_passphrase") else get_config("passphrase")])
	thread.start()
	return json.dumps({"result":"ok"})

@app.route("/generate",methods=["GET","POST"])
@has_ability("GENERATE_PREVIEW")
def generate():
	key_data = []

	servers = Server.select().order_by(Server.alias.asc())
	for server in servers:
		cur_server = {"alias":server.alias,"ip":server.ip,"port":server.port,"users":[]}
		server_users = User.select().where(User.server == server.id).order_by(User.user.asc())
		for server_user in server_users:
			cur_user = {"user":server_user.user,"password":server_user.password,"auth_file_location":server_user.auth_file_location,"keys":[]}
			user_people = Person.select().join(PeopleUsers).where(PeopleUsers.user == server_user)
			for user_person in user_people:
				person_keys = Key.select().join(PeopleKeys).where(PeopleKeys.person == user_person)
				for person_key in person_keys:
					cur_key = {"blob":person_key.blob,"algo":person_key.algo,"prefix":"" if person_key.prefix is None else person_key.prefix,"person":user_person.email}
					cur_user["keys"].append(cur_key)
			cur_server["users"].append(cur_user)
		key_data.append(cur_server)
	return full_minify(render_template("generate.html",key_data=key_data,data_count=len(key_data),sheck_public=get_config("management_key_public"),cur_datetime=time.strftime("%c")))

@app.route("/orc")
@has_ability(["ADD_ORC","EDIT_ORC","DELETE_ORC","EXECUTE_ORC","VIEW_ORC_RESULTS"])
def orc_list():
	orcs = ORC.select().order_by(ORC.alias.asc())
	return full_minify(render_template("orc/list.html",orcs=orcs))

class ORCAddForm(ParsleyForm):
	alias = wtforms.StringField("Alias")
	command = wtforms.StringField("Command")
	display_type = wtforms.SelectField("Display Type",choices=[("text","Text"),("historical","Historical")],default="text")
	schedule = wtforms.BooleanField("Scheduled ORC")
	hours = wtforms.StringField("Hours", default="0")
	minutes = wtforms.StringField("Minutes", default="0")
	seconds = wtforms.StringField("Seconds", default="0")

@app.route("/orc/add",methods=["GET","POST"])
@has_ability("ADD_ORC")
def orc_add_form():
	form = ORCAddForm(csrf_context=current_user.session)

	if request.method == "POST":
		form.process(request.form)
		if form.validate():
			orc_id = ORC.insert(alias=form.alias.data,command=form.command.data,display_type=form.display_type.data).execute()
			if form.schedule.data and get_config("store_passphrase") and current_user.has_ability("SCHEDULED_ORC"):
				ORCSchedule.insert(orc=orc_id,hours=form.hours.data,minutes=form.minutes.data,seconds=form.seconds.data).execute()
				recreate_schedule()
			add_log("Added ORC %s"%form.alias.data)
			return redirect(url_for("orc_list"))
	return full_minify(render_template("orc/add.html",form=form))

def recreate_schedule():
	with app.app_context():
		for job in sched.get_jobs():
			sched.unschedule_job(job)
		for orc in ORC.select():
			if orc.schedule.count()==1:
				schedule = orc.schedule.get()
				sched.add_interval_job(executeCommand, hours=schedule.hours, minutes=schedule.minutes, seconds=schedule.seconds, args=[orc.id,get_config("passphrase"),False])

@app.route("/orc/<orc_id>/edit",methods=["GET","POST"])
@has_ability("EDIT_ORC")
def orc_edit_form(orc_id):
	try:
		orc = ORC.get(ORC.id==orc_id)
		form = ORCAddForm(csrf_context=current_user.session)
		if request.method=="POST":
			form.process(request.form)
			if form.validate():
				orc.alias=form.alias.data
				orc.command=form.command.data
				orc.display_type=form.display_type.data
				orc.save()
				if get_config("store_passphrase") and current_user.has_ability("SCHEDULED_ORC"):
					ORCSchedule.delete().where(ORCSchedule.orc==orc_id).execute()
					if form.schedule.data:
						ORCSchedule.insert(orc=orc_id,hours=form.hours.data,minutes=form.minutes.data,seconds=form.seconds.data).execute()
					recreate_schedule()
				add_log("Edited ORC %s"%orc_id)
				return redirect(url_for("orc_list"))
		else:
			merged_obj_data = orc._data

			try:
				orc_schedule = ORCSchedule.get(ORCSchedule.orc == orc_id)
				merged_obj_data = dict(merged_obj_data.items()+orc_schedule._data.items())
				merged_obj_data["schedule"] = True
			except ORCSchedule.DoesNotExist:
				pass
			form.process(**merged_obj_data)
		return full_minify(render_template("orc/add.html",orc_id=orc.id,form=form))
	except ORC.DoesNotExist:
		flash("Invalid ORC","danger")

	return redirect(url_for("orc_list"))

@app.route("/orc/<orc_id>/delete")
@has_ability("DELETE_ORC")
def orc_delete(orc_id):
	try:
		orc = ORC.get(ORC.id==orc_id)
		ORCSchedule.delete().where(ORCSchedule.orc == orc_id).execute()
		ORCResult.delete().where(ORCResult.orc == orc_id).execute()
		orc.delete_instance()
		recreate_schedule()
		add_log("Deleted ORC %s"%orc_id)
	except ORC.DoesNotExist:
		flash("Invalid ORC","danger")
	return redirect(url_for("orc_list"))

@app.route("/orc/<orc_id>/execute",methods=["GET","POST"])
@has_ability("EXECUTE_ORC")
@requires_management
def orc_execute(orc_id):
	try:
		ORC.get(ORC.id==orc_id)
		add_log("Executing ORC %s"%orc_id)
		thread = Thread(target = executeCommand, args = [orc_id,request.form.get("passphrase") if not get_config("store_passphrase") else get_config("passphrase")])
		thread.start()
	except ORC.DoesNotExist:
		flash("Invalid ORC","danger")
	return redirect(url_for("orc_list"))

@app.route("/orc/<orc_id>/results")
@has_ability("VIEW_ORC_RESULTS")
def orc_results(orc_id):
	orc_exists = ORC.select(ORC, fn.Count(ORC.id).alias("count")).where(ORC.id==orc_id).get().count==1
	if orc_exists:
		orc = ORC.select().where(ORC.id==orc_id).first()
		orc_results = {"servers":[],"display_type":orc.display_type}
		for server in Server.select().order_by(Server.alias.asc()):
			new_server = {
				"alias":server.alias,
				"users":[]
			}
			for user in User.select().where(User.server == server).order_by(User.user.asc()):
				if orc.display_type=="historical":
					user_id = SQL("inner_query.user_id")
					result_list = SQL("inner_query.result_list")
					new_user = {
						"user":user.user,
						"result":",".join(reversed(ORCResult.select(
									user_id,
									fn.Group_Concat(result_list).alias("result_list_n")
								).from_(
									ORCResult.
										select(
											ORCResult.user.alias("user_id"),
											ORCResult.response.alias("result_list")
										).
										join(
											Server,
											on=(Server.id==ORCResult.server)
										).
										join(
											User,on=(User.id==ORCResult.user)
										).
										where(
											ORCResult.orc==orc_id,
											User.id==user.id
										).
										order_by(
											ORCResult.time.desc()
										).
										limit(
											30
										).
										alias("inner_query")
								).group_by(
									user_id
								).first().result_list_n.split(",")))
					}
				else:
					orc_result = ORCResult.select(
							ORCResult
						).join(
							Server,on=(ORCResult.server==Server.id)
						).join(
							User,on=(ORCResult.user==User.id)
						).order_by(
							Server.alias.asc(),User.user.asc(),ORCResult.time.desc()
						).where(
							ORCResult.orc==orc_id,User.id==user.id
						).limit(
							1
						).first()

					new_user = {
						"user":user.user,
						"result":"" if orc_result is None else orc_result.response
					}
				new_server["users"].append(new_user)
			orc_results["servers"].append(new_server)
		return full_minify(render_template("orc/results.html",orc=orc,orc_results=orc_results))
	else:
		return redirect(url_for("orc_list"))

@app.route("/log/<log_ts>")
@has_ability("LOGS")
def get_log(log_ts):
	log_rows = []
	if log_ts!="0":
		selected_datetime = datetime.datetime.utcfromtimestamp((int(log_ts)+1)//1000).replace(microsecond=(int(log_ts)+1)%1000*1000)
		log_entries = Log.select().order_by(Log.time.desc(),Log.id.desc()).limit(30).where(Log.time>selected_datetime)
	else:
		log_entries = Log.select().order_by(Log.time.desc(),Log.id.desc()).limit(30)
	for entry in log_entries:
		if int(time.mktime(entry.time.timetuple())*1e3 + entry.time.microsecond/1e3)>int(log_ts):
			log_rows.insert(0,{"t":"%s"%entry.time,"ts":int(time.mktime(entry.time.timetuple())*1e3 + entry.time.microsecond/1e3),"d":entry.data,"i":entry.id})
	return json.dumps(log_rows)

@app.route("/login",methods=["GET"])
@is_installed
@anonymous_required
def login_form():
	return full_minify(render_template("login.html"))

@app.route("/login",methods=["POST"])
@is_installed
@anonymous_required
def login():
	email = request.form.get("email")
	password = request.form.get("password")
	registered_user = Person.select().where(Person.email == email).first()
	if registered_user is not None:
		hashed_password = md5_hash("%s%s"%(password,registered_user.salt))
		if hashed_password==registered_user.password:
			login_user(registered_user)
			return redirect(url_for("server_list"))
		else:
			flash("Invalid login details","danger")
			return redirect(url_for("login_form"))
	else:
		flash("Invalid login details","danger")
		return redirect(url_for("login_form"))

@app.route("/logout",methods=["GET"])
@login_required
def logout():
	logout_user()
	return redirect(url_for("login_form"))

@app.route("/settings",methods=["GET"])
@login_required
def settings_form():
	return full_minify(render_template("settings.html"))

@app.route("/settings",methods=["POST"])
@login_required
def settings():
	password = request.form.get("current_password")
	new_password = request.form.get("new_password")
	confirm_new_password = request.form.get("confirm_new_password")

	if get_config("use_otp"):
		otp = request.form.get("otp")
		secret = current_user.secret
		otp_now = pyotp.TOTP(secret).now()
		otp_valid = str(otp_now)==str(otp)
	else:
		otp_valid = True

	if new_password != "":
		hashed_password = md5_hash("%s%s"%(password,current_user.salt))
		if hashed_password == current_user.password and otp_valid and new_password==confirm_new_password and len(new_password)>=8:
			salt = md5_hash(id_generator())
			Person.update(salt=salt,password=md5_hash("%s%s"%(new_password,salt))).where(Person.id==current_user.id).execute()
			flash("Password Updated","success")
		else:
			flash("Incorrect Credentials","danger")
			return full_minify(render_template("settings.html"))

	if "key" in request.files:
		key_content = request.files["key"].stream.read()
		if key_content != "":
			key_passphrase = request.form.get("key_passphrase")
			store_passphrase = request.form.get("store_passphrase")=="on"

			if not check_private_key_valid(key_content,key_passphrase):
				flash("Invalid key file, or incorrect passphrase","danger")
				return full_minify(render_template("settings.html"))
			set_config("management_key",key_content)
			set_config("management_key_public",get_keystring_from_privkey(key_content,request.form.get("key_passphrase")))

			set_config("store_passphrase",store_passphrase)
			if store_passphrase:
				set_config("passphrase",key_passphrase)
			else:
				set_config("passphrase","")
			flash("Updated Management Key","success")

	return full_minify(render_template("settings.html"))




@app.route("/install",methods=["GET"])
def install_form():
	if Person.select().count()>0:
		return full_minify(render_template("error/401.html")),401
	else:
		return full_minify(render_template("install/install.html"))

@app.route("/install",methods=["POST"])
def install():
	if Person.select().count()>0:
		return full_minify(render_template("error/401.html")),401
	else:
		key_content = request.files["key"].stream.read()
		key_passphrase = request.form.get("key_passphrase")
		if not check_private_key_valid(key_content,key_passphrase):
			flash("Invalid key file, or incorrect passphrase","danger")
			return full_minify(render_template("install/install.html"))
		set_config("management_key",key_content)
		set_config("management_key_public",get_keystring_from_privkey(key_content,request.form.get("key_passphrase")))

		email = request.form.get("email")
		alias = request.form.get("alias")
		store_passphrase = request.form.get("store_passphrase")=="on"
		use_otp = request.form.get("use_otp")=="on"
		set_config("store_passphrase",store_passphrase)
		if store_passphrase:
			set_config("passphrase",key_passphrase)
		set_config("use_otp",use_otp)

		password = id_generator()
		salt = md5_hash(id_generator())
		password_hash = md5_hash("%s%s"%(password,salt))
		if use_otp:
			secret = pyotp.random_base32()
		else:
			secret = None
		person_id=Person.insert(alias=alias,email=email,password=password_hash,salt=salt,secret=secret).execute()
		for ability in Ability.select():
			PeopleAbilities.insert(person=person_id,ability=ability.id).execute()
		flash("First user created - check email for login details","success")

		if use_otp:
			qr = qrcode.make("otpauth://totp/sheck?secret=%s"%(secret))
			img_io = StringIO.StringIO()
			qr.save(img_io, 'PNG')
			img_io.seek(0)
			qrcode_data = img_io.read()
			send_email("Welcome to Sheck",
				[email],
				render_template("install/email_install.txt",alias=alias,password=password),
				render_template("install/email_install.html",alias=alias,password=password),
				[("qrcode.png",qrcode_data,"image/png")]
			)
		else:
			send_email("Welcome to Sheck",
				[email],
				render_template("install/email_install.txt",alias=alias,password=password),
				render_template("install/email_install.html",alias=alias,password=password)
			)
		return redirect(url_for("login_form"))

@app.route("/")
def home():
	if Person.select().count()==0:
		return redirect(url_for("install_form"))
	else:
		if current_user.is_authenticated():
			if current_user.has_ability(["ADD_SERVER","DELETE_SERVER","ADD_USER","DELETE_USER","REQUEST_SERVER_ACCESS","GRANT_SERVER_ACCESS"]):
				return redirect(url_for("server_list"))
			elif current_user.has_ability(["ADD_PERSON","DELETE_PERSON","ASSIGN_KEY_TO_PERSON","ASSIGN_ACCESS_TO_PERSON","EDIT_PERSON_ABILITIES"]):
				return redirect(url_for("people_list"))
			elif current_user.has_ability("ADD_KEY"):
				return redirect(url_for("key_list"))
			elif current_user.has_ability("GENERATE_PREVIEW"):
				return redirect(url_for("generate_preview"))
			elif current_user.has_ability(["ADD_ORC","DELETE_ORC","EXECUTE_ORC","VIEW_ORC_RESULTS"]):
				return redirect(url_for("orc_list"))
			else:
				return full_minify(render_template("error/401.html")),401
		else:
			return redirect(url_for("login"))

@app.route("/debug")
def debug():
	assert app.debug == False

@app.errorhandler(401)
def access_denied(e):
	return full_minify(render_template("error/401.html")), 401

@app.errorhandler(404)
def file_not_found(e):
	return full_minify(render_template("error/404.html")), 404

def set_config(config_key,value):
	if isinstance(value,basestring) or isinstance(value,bool) or isinstance(value,int):
		if SheckConfig.select().where(SheckConfig.key==config_key).first() is None:
			SheckConfig.insert(key=config_key,value=pickle.dumps(value)).execute()
		else:
			SheckConfig.update(value=pickle.dumps(value)).where(SheckConfig.key==config_key).execute()

def get_config(config_key,default_value=None):
	config_item = SheckConfig.select().where(SheckConfig.key==config_key).first()
	if config_item is None:
		return default_value
	else:
		return pickle.loads(config_item.value)

app.jinja_env.globals.update(get_config=get_config)
app.jinja_env.globals.update(is_installed=check_is_installed)

class Key(db.Model):
	comment = CharField()
	algo = CharField()
	blob = TextField()
	prefix = CharField()
	fingerprint = CharField()

class Log(db.Model):
	data = CharField()
	time = DateTimeField(default=datetime.datetime.now)

class Person(db.Model):
	alias = CharField()
	email = CharField()
	password = CharField(max_length=32)
	salt = CharField(max_length=32)
	secret = CharField(null=True)
	session = {}

	def has_ability(self,ability):
		if type(ability) is list:
			for ability_ in ability:
				for user_ability in self.abilities:
					if user_ability.ability.key == ability_:
						return True
		else:
			for user_ability in self.abilities:
				if user_ability.ability.key == ability:
					return True
		return False

	def is_authenticated(self):
		return True

	def is_active(self):
		return True

	def is_anonymous(self):
		return False

	def get_id(self):
		return self.id

	def __unicode__(self):
		return self.alias

class Server(db.Model):
	ip = CharField(max_length=15)
	port = IntegerField(default=22)
	alias = CharField()

class User(db.Model):
	server = ForeignKeyField(Server, related_name="users")
	user = CharField()
	password = CharField(null=True)
	auth_file_location = CharField(default="~/.ssh/authorized_keys",null=True)

class PeopleKeys(db.Model):
	person = ForeignKeyField(Person, related_name="keys")
	key = ForeignKeyField(Key, related_name="people")

class PeopleUsers(db.Model):
	person = ForeignKeyField(Person, related_name="users")
	user = ForeignKeyField(User, related_name="people")

class ORC(db.Model):
	alias = CharField()
	command = CharField()
	display_type = CharField(default="text")
	last_run = DateTimeField(default=datetime.datetime.now)

class ORCSchedule(db.Model):
	orc = ForeignKeyField(ORC, related_name="schedule")
	hours = IntegerField()
	minutes = IntegerField()
	seconds = IntegerField()

class ORCResult(db.Model):
	server = ForeignKeyField(Server, related_name="orc_results")
	user = ForeignKeyField(User)
	orc = ForeignKeyField(ORC, related_name="results")
	response = CharField()
	time = DateTimeField(default=datetime.datetime.now)

class AbilityCategory(db.Model):
	alias = CharField()

class Ability(db.Model):
	alias = CharField()
	key = CharField()
	category = ForeignKeyField(AbilityCategory, related_name="abilities")

class PeopleAbilities(db.Model):
	person = ForeignKeyField(Person, related_name="abilities")
	ability = ForeignKeyField(Ability)

class AccessRequest(db.Model):
	person = ForeignKeyField(Person,related_name="requests")
	user = ForeignKeyField(User,related_name="requests")
	time = DateTimeField(default=datetime.datetime.now)
	granted = BooleanField(default=False)

class SheckConfig(db.Model):
	key = CharField()
	value = TextField()

first_run = ((db.database_engine=="peewee.MySQLDatabase" or db.database_engine=="peewee.PostgresqlDatabase") and not SheckConfig.table_exists()) or (db.database_engine=="peewee.SqliteDatabase" and not os.path.exists(app.config["DATABASE"]["name"]))

Key.create_table(fail_silently=True)
Log.create_table(fail_silently=True)
Person.create_table(fail_silently=True)
Server.create_table(fail_silently=True)
User.create_table(fail_silently=True)
PeopleKeys.create_table(fail_silently=True)
PeopleUsers.create_table(fail_silently=True)
ORC.create_table(fail_silently=True)
ORCSchedule.create_table(fail_silently=True)
ORCResult.create_table(fail_silently=True)
AbilityCategory.create_table(fail_silently=True)
Ability.create_table(fail_silently=True)
PeopleAbilities.create_table(fail_silently=True)
AccessRequest.create_table(fail_silently=True)
SheckConfig.create_table(fail_silently=True)

if first_run:
	server_cat_id = AbilityCategory.insert(alias="Server").execute()
	person_cat_id = AbilityCategory.insert(alias="Person").execute()
	misc_cat_id = AbilityCategory.insert(alias="Misc").execute()
	orc_cat_id = AbilityCategory.insert(alias="ORC").execute()

	Ability.insert(alias="Add Server",key="ADD_SERVER",category=server_cat_id).execute()
	Ability.insert(alias="Edit Server",key="EDIT_SERVER",category=server_cat_id).execute()
	Ability.insert(alias="Delete Server",key="DELETE_SERVER",category=server_cat_id).execute()
	Ability.insert(alias="Request Server Access",key="REQUEST_SERVER_ACCESS",category=server_cat_id).execute()
	Ability.insert(alias="Grant Server Access",key="GRANT_SERVER_ACCESS",category=server_cat_id).execute()
	Ability.insert(alias="Add User",key="ADD_USER",category=server_cat_id).execute()
	Ability.insert(alias="Edit User",key="EDIT_USER",category=server_cat_id).execute()
	Ability.insert(alias="Delete User",key="DELETE_USER",category=server_cat_id).execute()
	Ability.insert(alias="Add Person",key="ADD_PERSON",category=person_cat_id).execute()
	Ability.insert(alias="Edit Person",key="EDIT_PERSON",category=person_cat_id).execute()
	Ability.insert(alias="Delete Person",key="DELETE_PERSON",category=person_cat_id).execute()
	Ability.insert(alias="Edit Person Abilities",key="EDIT_PERSON_ABILITIES",category=person_cat_id).execute()
	Ability.insert(alias="Assign Key to Person",key="ASSIGN_KEY_TO_PERSON",category=person_cat_id).execute()
	Ability.insert(alias="Assign Access to Person",key="ASSIGN_ACCESS_TO_PERSON",category=person_cat_id).execute()
	Ability.insert(alias="Add Key",key="ADD_KEY",category=misc_cat_id).execute()
	Ability.insert(alias="Generate Preview",key="GENERATE_PREVIEW",category=misc_cat_id).execute()
	Ability.insert(alias="Generate Write",key="GENERATE_WRITE",category=misc_cat_id).execute()
	Ability.insert(alias="Add ORC",key="ADD_ORC",category=orc_cat_id).execute()
	Ability.insert(alias="Edit ORC",key="EDIT_ORC",category=orc_cat_id).execute()
	Ability.insert(alias="Delete ORC",key="DELETE_ORC",category=orc_cat_id).execute()
	Ability.insert(alias="Execute ORC",key="EXECUTE_ORC",category=orc_cat_id).execute()
	Ability.insert(alias="View ORC Results",key="VIEW_ORC_RESULTS",category=orc_cat_id).execute()
	Ability.insert(alias="Create Scheduled ORC",key="SCHEDULED_ORC",category=orc_cat_id).execute()
	Ability.insert(alias="View Logs",key="LOGS",category=misc_cat_id).execute()
	Ability.insert(alias="Rescan",key="RESCAN",category=misc_cat_id).execute()
	Ability.insert(alias="Update Management Settings",key="UPDATE_MANAGEMENT",category=misc_cat_id).execute()

if __name__ == "__main__":
	app.run(host="0.0.0.0",use_reloader=True,port=5000,extra_files=["config.py"],threaded=False)
else:
	recreate_schedule()