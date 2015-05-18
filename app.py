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

import memcache
mc = memcache.Client(['127.0.0.1:11211'], debug=0)
'''
mc.set("some_key", "Some value", time=1*60)
value = mc.get("some_key")
'''

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/auth/login", AuthHandler),
            (r"/auth/logout", LogoutHandler),
            (r"/rest/", MainRestHandler),
            (r"/rest/login", LoginRestHandler),
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
                'expires_days': 1,
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
               'token_memcache': value,
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


# Rest Auth
class BaseAuthHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.app.db

    @tornado.gen.coroutine
    def get_current_user(self):
        auth_header = self.request.headers.get('Authorization')
        if auth_header is None or not auth_header.startswith('Basic '):
            return False

        auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
        # login, password = auth_decoded.split(':', 2)
        token = auth_decoded.split(':')
        auth_found = yield self.get_token(token[0])

        if auth_found:
            self.request.headers.add('auth', auth_found)
            return True
        else:
            return False

    @tornado.gen.coroutine
    def get_token(self, token):
        get_valid_token = mc.get("user_token")
        if token == get_valid_token:
            return True
        return False


class MainRestHandler(BaseAuthHandler):
    '''
    curl -X GET -v -H "Accept: application/json" http://demotoken@127.0.0.1:5555/hello
    '''
    @tornado.gen.coroutine
    def get(self):
        get_perm = yield self.get_current_user()
        print(get_perm)
        if get_perm:
            self.set_status(200)
            self.set_header('WWW-Authenticate', 'basic realm="Authenticate"')
            access_status = {'Access Free': 'Fly Free'}
        else:
            self.set_status(401)
            self.set_header('WWW-Authenticate', 'basic realm="Restricted"')
            access_status = {'Access Restricted': 'im sorry...'}
        self.write(access_status)


class LoginRestHandler(BaseAuthHandler):
    '''
    curl -X POST -v -H "Accept: application/json" -d "username=demo&password=demo" http://127.0.0.1:5555/login
    '''
    def post(self):
        print(self.request)
        getusername = self.get_argument("username")
        getpassword = self.get_argument("password")
        if "demo" == getusername and "demo" == getpassword:
            # Create Token and Database insert
            import uuid
            get_token = uuid.uuid4().hex
            mc.set("user_token", get_token, time=1*60)
            get_randon_valid_token = 'demotoken'
            self.write({'You Token Is': get_token})
        else:
            self.write({'User not register': 'Restrict'})


if __name__ == '__main__':
    parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    print('server started ...{0}'.format(options.port))
    tornado.ioloop.IOLoop.instance().start()

