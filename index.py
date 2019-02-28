#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import requests
import urllib
from http.server import BaseHTTPRequestHandler, HTTPServer
import random
import string
from webbrowser import open_new
import configparser


def main():
    config = configparser.ConfigParser()
    config.read("./config/config.ini")

    api_key = config["firebase_config"]["api_key"]
    email = config["email_and_password"]["email"]
    password = config["email_and_password"]["password"]

    user = sign_in_with_email_and_password(api_key, email, password, config)

    print('---- sign_in_with_email_and_password -----')
    print_pretty(user)
    print(user['idToken'])

    user = sign_in_with_popup(api_key, config)

    print('---- sign_in_with_popup -----')
    print_pretty(user)
    print(user['idToken'])


def sign_in_with_email_and_password(api_key, email, password, config):
    """
    Firebaseで認証を行う(SDKの signInWithEmailAndPassword )
    :param api_key:
    :param email:
    :param password:
    :return: Firebaseの、idTokenなどを含んだ、認証情報
    """
    # https://firebase.google.com/docs/reference/rest/auth/#section-sign-in-email-password
    uri = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={api_key}"
    headers = {"Content-type": "application/json"}
    data = json.dumps({"email": email, "password": password, "returnSecureToken": True})
    proxies, verify = get_proxy(config)

    result = requests.post(url=uri,
                           headers=headers,
                           data=data,
                           proxies=proxies,
                           verify=verify)
    return result.json()


def sign_in_with_popup(api_key, config):
    """
    Firebaseで認証を行う(SDKの signInWithPopup )
    :param api_key:
    :param config:
    :return:
    """
    id_token, request_path = get_id_token(config)
    print(id_token)
    print(request_path)
    return sign_in_with_id_token(api_key, id_token, request_path, config)


def sign_in_with_id_token(api_key, id_token, request_path, config):
    """
    Firebaseが OAuth 2.0 client となる OAuthプロバイダの id_tokenを持ち込んで、Firebaseの認証を行う
    :param api_key:
    :param id_token:
    :param request_path:
    :param config:
    :return:
    """

    # https://firebase.google.com/docs/reference/rest/auth/#section-link-with-oauth-credential
    uri = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyAssertion?key={api_key}"
    headers = {"Content-type": "application/json"}

    # request_uri = f"http://localhost:8080{request_path}"
    # urllib.parse.quote(request_uri_tmp)
    data_obj = {
        "postBody": f"id_token={id_token}&providerId=google.com",
        "requestUri": f"http://localhost:8080{request_path}",
        "returnIdpCredential": True,
        "returnSecureToken": True
    }

    proxies, verify = get_proxy(config)
    result = requests.post(url=uri,
                           headers=headers,
                           data=json.dumps(data_obj),
                           proxies=proxies,
                           verify=verify)
    return result.json()


def get_id_token(config):
    """
    OAuthを用いた認証を行うため、OAuthプロバイダの画面を開いて、WEBサーバを起動してリダイレクトされてくるのを待つ。
    :param config:
    :return:
    """
    state = random_string(40)

    client_id = config['oauth_config']['client_id']
    scope = config['oauth_config']['scope']
    redirect_uri = config['oauth_config']['redirect_url']
    authorization_endpoint = config['oauth_config']['authorization_endpoint']

    authorization_endpoint_w_param = f'{authorization_endpoint}' \
                                     f'?client_id={client_id}&' \
                                     f'redirect_uri={redirect_uri}&' \
                                     f'state={state}&' \
                                     f'response_type=code&' \
                                     f'scope={scope}'
    open_new(authorization_endpoint_w_param)

    def create_handler(request, address, server):
        return OAuthClient_Handler(
            request, address, server, config)

    httpServer = HTTPServer(('localhost', 8080), create_handler)
    httpServer.handle_request()

    return httpServer.id_token, httpServer.request_path


class OAuthClient_Handler(BaseHTTPRequestHandler):

    def __init__(self, request, address, server, config):
        self._config = config
        oauth_config = config['oauth_config']

        self._client_id = oauth_config['client_id']
        self._client_secret = oauth_config['client_secret']
        self._redirect_uri = oauth_config['redirect_url']
        self._token_endpoint = oauth_config['token_endpoint']

        super().__init__(request, address, server)

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain;charset=UTF-8')
        self.end_headers()

        # リダイレクトURLのクエリから、codeが取得できたらアクセストークンを取得する処理を動かす
        if 'code' in self.path:
            query = urllib.parse.parse_qs(self.path[2:])
            state = query['state'][0]  # 本来はCSRFをチェックするべき
            code = query['code'][0]

            token_endpoint = self._token_endpoint
            headers = {'Content-Type': self._config['oauth_config']['media_type']}

            token_params = {
                'redirect_uri': self._redirect_uri,
                'client_id': self._client_id,
                'client_secret': self._client_secret,
                'grant_type': 'authorization_code',
                'code': code
            }

            proxies, verify = get_proxy(self._config)
            response = requests.request(
                method='POST',
                url=token_endpoint,
                headers=headers,
                data=urllib.parse.urlencode(token_params),
                proxies=proxies,
                verify=verify
            )
            self.wfile.write(bytes('ログイン完了。ブラウザ閉じちゃってください。', 'utf-8'))

            self.server.id_token = response.json()['id_token']
            self.server.request_path = self.path

            print('---------------')
            print_pretty(response.json())
            print('---------------')


def random_string(n):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


def get_proxy(config):
    verify = True
    proxies = None

    if config["proxy"].getboolean("proxy"):
        proxies = {
            "http": config["proxy"]["http"],
            "https": config["proxy"]["https"]
        }
        verify = False

    return proxies, verify


def print_pretty(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=4, sort_keys=True, separators=(',', ': ')))


if __name__ == '__main__':
    main()
