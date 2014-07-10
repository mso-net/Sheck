Sheck
=====

### Key Management

Sheck is an easy to use SSH Key and Server Management Tool, which aims to make the life of the sys-admin easier when it comes to performing SSH Key audits.

Using Sheck, you are able to manage Public Keys on any number of Linux servers from a simple, intuitive interface. The following is a basic work-flow using Sheck.

- A *Management Key* is defined upon setup of Sheck
- A *Server* has *Users* associated with it (i.e. root, administrator, webmaster)
- *Users* have an *Authorized Keys* path, to which *Keys* are read, and written
- *People* are your staff members, and are defined by an *Email Address* / *Password* pair
- *Public Keys* can be added, and assigned to specific *People*
- *People* can be granted access to specific *Users*
- *Authorized Key* files are generated and written to the appropriate locations, utilizing SFTP connections, authorized by the *Management Key* added during setup of Sheck
- *Public Keys* may be imported from current *Servers* and their *Users*. These will be checked for uniqueness using their *Public Key Fingerprint*

### ORCs
ORCs (or One-line Returning Commands..catchy, huh?) enable you to run commands on servers én-masse, and inspect the output. ORCs can be made to treat the returning data as a block of text, or it can be treated as a numeric for historical purposes. ORCs can also be scheduled to run at specific intervals (for this, the *Management Key Passphrase* must be stored).

One example would be an ORC to check the current 1 minute average load for servers.

```
uptime|awk '{print $(NF-2)}'|grep -v average|sed -r 's/,//g'
```

The above command returns the 1 minute load average. If the Display Type of *historical* is chosen when adding the ORC, the values returned will be stored against a time stamp, and rendered in a line graph when viewing the ORC results.

Another example would be keeping an eye on free disk space. For this example, the ORC will be added with a Display Type of *text*

```
df -h
```

This time when we view the results for the ORC, the text returned from the command is displayed against each *Server* and *User*.

#### Warning:
ORCs are an extremely powerful, and subsequently dangerous tool. The method for executing these commands is simply an SSH session, authorized with the *Management Key* and stored *Management Key Passphrase*. This is by no means an ideal situation, due to the fact if the database is compromised, so are all your servers. While we encourage you to play with ORCs, we also urge you to be very careful, as commands WILL be executed, regardless of their content.

In the future, we could improve upon the ORC feature by implementing something like an agent which is furnished with specific abilities, or by specifying a limited set of commands (to monitor common metrics) that are made available to the user when creating an ORC. Until then, be careful.

Installation
--------------

Sheck can be deployed either on a server you control, or on a Heroku node.

### Linux server

In order to install Sheck on a linux server, you must have the following packages installed.

- python2.7
- python-dev
- python-pip
- build-essential

Additional packages may be required by the Python packages that are installed by the below script - simply install any dependencies that *pip* states are missing.

```
git clone https://github.com/mso-net/Sheck.git
cd Sheck
chmod +x install_deps.sh
./install_deps.sh
```

Once all of the dependencies have been installed, edit *config.py* and set your *SECRET_KEY*, *MAIL_SERVER*, *MAIL_DEFAULT_SENDER* and *DATABASE* details. You can use either MySQL or SQLite.

When you have finished configuring Sheck, you can run it by using either of the following commands

```
# Run in production mode (faster, no realtime debugging)
python run.py

# Run in development mode (slower, realtime debugging)
python sheck.py
```

Your sheck instance should then be available on via *http://<ip address>:5000*

On the first visit to Sheck, you will be prompted to fill in some details, such as your *Email Address*, *Management Key* and whether or not you wish to use *OTP Authentication*, and whether you want to store the *Management Key Passphrase*.

### Heroku node

While Sheck CAN be deployed via Heroku, we recommend that you're very cautious when configuring it. We recommend that the *Management Key Passphrase* should not be stored, and that *OTP Authentication* is enabled.

On to the good stuff..Heroku makes it VERY easy to deploy applications with a few simple commands.

```
git clone https://github.com/mso-net/Sheck.git
cd Sheck
heroku create
heroku addons:add cleardb
heroku addons:add sendgrid
git push heroku master
heroku ps:scale web=1
heroku open
```

That's it! Heroku will automatically install all of the dependencies, and Sheck will automatically pick up configuration values for SMTP/MySQL (note that the *MAIL_DEFAULT_SENDER* configuration value will NOT be changed.


Usage
---
We will be putting together a few short videos to show what you can do with Sheck, and how to do it, however we believe that Sheck is intuitive enough to be used by anyone that is vaguely familiar with Linux systems.

Contributing
---
Sheck is licensed under GPLv3, and all contributes are welcome! We're also more than willing to act on feature requests, if you think something essential is missing from Sheck.

Version
----

0.1

Tech
-----------

Sheck uses a number of open source projects to work properly:

* [apscheduler] - Advanced Python Scheduler
* [bootstrap] - Bootstrap is the most popular HTML, CSS, and JS framework for developing responsive, mobile first projects on the web.
* [bootstrap-ubuntu] - A free Bootstrap theme from Bootswatch
* [flask] - A microframework based on Werkzeug, Jinja2 and good intentions
* [flask-assets] - Flask webassets integration
* [flask-login] - Flask user session management
* [flask-mail] - A Flask extension providing simple email sending capabilities
* [flask-peewee] - Flask integration for peewee, including admin, authentication, rest 
* [htmlmin] - A configurable HTML Minifier with safety features
* [jquery] - Write less, do more
* [jquery-multiselect] - A user-friendlier drop-in replacement for the standard <select> with multiple attribute activated
* [jquery-peity] - Progressive <svg> pie charts
* [jquery-timeago] - A jQuery plugin that makes it easy to support automatically updating fuzzy timestamps
* [paramiko] - Python SSH Module
* [parsleyjs] - The ultimate javascript form validation library
* [peewee] - A small, expressive orm -- supports postgresql, mysql and sqlite
* [pyotp] - Python One Time Password library
api and more
* [wtforms] - A flexible forms validation and rendering library for Python

License
----

GPLv3

[paramiko]:https://github.com/paramiko/paramiko
[pyotp]:https://github.com/nathforge/pyotp
[wtforms]:https://github.com/wtforms/wtforms
[flask]:https://github.com/mitsuhiko/flask
[flask-mail]:https://bitbucket.org/danjac/flask-mail
[flask-login]:https://github.com/maxcountryman/flask-login
[flask-assets]:https://github.com/miracle2k/flask-assets
[htmlmin]:https://github.com/mankyd/htmlmin/
[peewee]:https://github.com/coleifer/peewee/
[flask-peewee]:https://github.com/coleifer/flask-peewee
[bootstrap]:http://getbootstrap.com
[jquery]:https://jquery.com/
[jquery-multiselect]:http://loudev.com/
[jquery-timeago]:http://timeago.yarp.com/
[jquery-peity]:https://benpickles.github.io/peity/
[parsleyjs]:http://parsleyjs.org/
[bootstrap-ubuntu]:http://bootswatch.com/
[apscheduler]:https://pythonhosted.org/APScheduler/