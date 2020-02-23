import flask_login
from flask_login import UserMixin

class EgaUser(flask_login.UserMixin):
    def __init__(self, ega_id, ega_secret=None):
        self.ega_id = ega_id
        self.ega_secret = ega_secret
        UserMixin.__init__(self)
    def get_id(self):
           return (self.ega_id)
    def get_secret(self):
           return (self.ega_secret)
    pass