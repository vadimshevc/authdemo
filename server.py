import base64
import hmac
import json
import hashlib

from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "9c6f6a439faebe40954c0a820d79854d037b1b3bd37fcf2157849dcdf847450d"
PASSWORD_SALT = "32d564b194f3e2ef5f4222929d048f27265b12c733a636ab5c7400814f3a0d34"

def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    password_hash =  hashlib.sha256( (password + PASSWORD_SALT).encode() )\
        .hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash
        
users = {
    "bandera@user.com": {
        "name": "Alexey",
        "password": "448642559d353b56dfd9eeaaf7e0613505b964a2313d68630d2de6674d88e252",
        "balance": 100_000
    },
    "petr@user.com": {
        "name": "Petr",
        "password": "2df1277ef10a10967cea9821bd2c30f04e97e99b4772f291f798bea5159221ab",
        "balance": 555_555
    }
}

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        responce = Response(login_page, media_type="text/html")
        responce.delete_cookie(key="username")
        return responce
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />" 
        f"Баланс: {users[valid_username]['balance']}", media_type="text/html")


@app.post("/login")
def process_login_page(data: dict = Body(...)):
        username = data["username"]
        password = data["password"]
        user = users.get(username)
        if not user or not verify_password(username, password):
            return Response(
                json.dumps({
                    "success": False,
                    "message": "Я вас не знаю!"
                }),
                media_type="application/json")
        
        responce = Response(
            json.dumps({
                "success": True,
                "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}"
            }),
            media_type='application/json')
        
        username_signed = base64.b64encode(username.encode()).decode() + "." + \
            sign_data(username)
        responce.set_cookie(key="username", value=username_signed)
        return responce