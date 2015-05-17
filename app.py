import base64
import tornado.web
import tornado.ioloop
import tornado.escape
import tornado.httpserver
from tornado.options import define, options, parse_command_line
from pycket.session import SessionMixin
import uuid

import os.path

define("port", default=5555, help="run on the given port", type=int)
define("database", default='test', help="run on the database")

base_dir = os.path.dirname(__file__)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/auth/login", AuthHandler),
            (r"/auth/logout", LogoutHandler),
        ]
        settings = dict(
            cookie_secret="32oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            debug=True,
            login_url="/auth/login",
            logout_url="/auth/logout",
        )

        settings['pycket'] = {
            'engine': 'memcached',
            'storage': {
                'servers': ('localhost:11211',)
            },
            'cookies': {
                'expires_days': 120,
            },
        }

        tornado.web.Application.__init__(self, handlers, **settings)



class BaseHandler(tornado.web.RequestHandler, SessionMixin):
    def get_current_user(self):
        user = self.session.get('user')
        if not user:
            return None
        return user


class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        token = tornado.escape.xhtml_escape(self.current_user)
        obj = {'user_token': token,
               'url_logout': '/auth/logout',
               'obj_user': 'obj data user',
        }
        self.write(obj)


class AuthHandler(BaseHandler, SessionMixin):

    def get(self):
        self.write('<form method="post">'
                   'Enter your username: <input name="username" type="text"><br>'
                   'Enter your password: <input name="password" type="password">'
                   '<button type="submit" class="btn">Login</button></form>')

    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')
        if username == 'demo' and password == 'demo':
            get_valid_token = uuid.uuid4().hex
            self.session.set('user', get_valid_token)
            self.redirect('/')            
        else:
            self.write({'status':'login nao encontrado'})


class LogoutHandler(BaseHandler, SessionMixin):
    def get(self):
        self.session.delete('user')
        self.redirect("/")


if __name__ == '__main__':
    parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    print('server started ...{0}'.format(options.port))
    tornado.ioloop.IOLoop.instance().start()

