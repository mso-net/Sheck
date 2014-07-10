import os
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from sheck import app

if __name__ == "__main__":
	http_server = HTTPServer(WSGIContainer(app))
	http_server.listen(int(os.environ.get("PORT", 5000)))
	IOLoop.instance().start()