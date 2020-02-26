import flask_login

class EgaUser(flask_login.UserMixin):
    def __init__(self, ega_id, ega_secret=None):
        self.ega_id = ega_id
        self.ega_secret = ega_secret
        super()
    def get_id(self):
        return (self.ega_id)
    def get_secret(self):
        return (self.ega_secret)
