import flask_login

class EgaUser(flask_login.UserMixin):
    def __init__(self, ega_id, ega_password=None):
        self.ega_id = ega_id
        self.ega_password = ega_password
        super()
    def get_id(self):
        return self.ega_id
    def get_password(self):
        return self.ega_password
