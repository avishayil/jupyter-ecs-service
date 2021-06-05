# Configuration file for Jupyter Hub

import os
import sys
from oauthenticator.generic import LocalGenericOAuthenticator

join = os.path.join

here = os.path.dirname(__file__)
root = os.environ.get('OAUTHENTICATOR_DIR', here)
sys.path.insert(0, root)

c = get_config()

c.JupyterHub.log_level = 10
c.JupyterHub.admin_users = admin = set()

with open(join(root, 'admins')) as f:
    for line in f:
        if not line:
            continue
        parts = line.split()
        name = parts[0]
        admin.add(name)

c.JupyterHub.authenticator_class = LocalGenericOAuthenticator
c.JupyterHub.shutdown_on_logout = True

c.OAuthenticator.oauth_callback_url = os.environ.get('OAUTH_CALLBACK_URL')
c.OAuthenticator.client_id = os.environ.get('OAUTH_CLIENT_ID')
c.OAuthenticator.client_secret = os.environ.get('OAUTH_CLIENT_SECRET')

c.LocalGenericOAuthenticator.auto_login = True
c.LocalGenericOAuthenticator.create_system_users = True
c.LocalGenericOAuthenticator.add_user_cmd = ['adduser', '-q', '--gecos', '', '--disabled-password', '--force-badname']

c.LocalGenericOAuthenticator.login_service = os.environ.get('OAUTH_LOGIN_SERVICE_NAME')
c.LocalGenericOAuthenticator.username_key = os.environ.get('OAUTH_LOGIN_USERNAME_KEY')
c.LocalGenericOAuthenticator.authorize_url = os.environ.get('OAUTH_AUTHORIZE_URL')
c.LocalGenericOAuthenticator.token_url = os.environ.get('OAUTH_TOKEN_URL')
c.LocalGenericOAuthenticator.userdata_url = os.environ.get('OAUTH_USERDATA_URL')
c.LocalGenericOAuthenticator.scope = os.environ.get('OAUTH_SCOPE').split(',')
