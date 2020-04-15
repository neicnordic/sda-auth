import unittest
import requests
from bs4 import BeautifulSoup


class TestElixirAuth(unittest.TestCase):
    """ElixirAuth.
    Testing ElixirAuth."""

    def setUp(self):
        """Initialise authenticator."""
        self.backend_url = "http://localhost:31111/elixir/login"


    def tearDown(self):
        """Finalise test."""
        print("Finishing test")


    def test_elixir_login(self):
        """Test that the login endpoint is active."""
        session_response = requests.get(self.backend_url,
                                allow_redirects=False)
        print("Session id response")

        session_id = session_response.cookies['session']
        location = session_response.headers['location']

        print(session_id)
        print(location)

        self.assertEqual(session_response.status_code, 302)
        self.assertIsNotNone(session_id)

        grant_response = requests.get(location,
                                allow_redirects=False)

        print("Grant response")
        location = grant_response.headers['location']
        grant_id = location.split('/').pop()
        print(grant_id)
        print(location)

        self.assertEqual(grant_response.status_code, 302)
        self.assertIsNotNone(grant_id)

        oidc_url = f'http://localhost:9090{location}/submit'
        cookies = {"_grant": grant_id}
        creds_payload = {"view":'login',
                         "login":'dummy',
                         "password":'dummy',
                         "submit": ''}

        oidc_response = requests.post(oidc_url,
                                allow_redirects=True,
                                data=creds_payload,
                                cookies=cookies)

        print("Authentication response")
        location = oidc_response.url
        self.assertEqual(oidc_response.status_code, 200)
        self.assertIs(self.backend_url in location, True)

class TestEGAAuth(unittest.TestCase):
    """EgaAuth.
    Testing EgaAuth."""

    def setUp(self):
        """Initialise authenticator."""
        self.backend_url = "http://localhost:31111/ega/login"
        self.user_info_url = "http://localhost:31111/ega/info"


    def tearDown(self):
        """Finalise test."""
        print("Finishing test")


    def test_ega_login(self):
        """Test that the login endpoint is active."""
        session_response = requests.get(self.backend_url,
                                        allow_redirects=False)

        print("Session id response")
        session_id = session_response.cookies['session']
        print(session_id)

        self.assertEqual(session_response.status_code, 200)
        self.assertIsNotNone(session_id)

        soup = BeautifulSoup(session_response.content, 'html.parser')

        csrf_token = soup.find('input', {'id': 'csrf_token'}).get('value')
        print(csrf_token)

        cookies = {"session": f'{session_id}'}
        creds_payload = {"csrf_token": csrf_token,
                         "username":'dummy',
                         "password":'dummy',
                         "submit": 'log+in'}

        login_response = requests.post(self.backend_url,
                                       allow_redirects=False,
                                       data=creds_payload,
                                       cookies=cookies)

        print("Authentication response")
        destination = login_response.headers['location']
        self.assertEqual(destination, self.user_info_url)
