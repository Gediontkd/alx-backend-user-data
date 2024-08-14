#!/usr/bin/env python3
"""
Main file
"""
import requests


def register_user(email: str, password: str) -> None:
    """this method registers a new user"""
    form_data = {
        "email": email,
        "password": password
    }
    response = requests.post("http://localhost:5000/users", data=form_data)
    data = response.json()
    if response.status_code == 400:
        assert data["message"] == "email already registered"
    else:
        assert data["email"] == email
        assert data["message"] == "user created"
    return None


def log_in_wrong_password(email: str, password: str) -> None:
    """this method logs in a user with wrong password"""
    form_data = {
        "email": email,
        "password": password
    }
    response = requests.post("http://localhost:5000/sessions", data=form_data)
    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """this method logs in a user with right password"""
    form_data = {
        "email": email,
        "password": password
    }
    response = requests.post("http://localhost:5000/sessions", data=form_data)
    data = response.json()
    if response.status_code == 200:
        assert data["email"] == email
        assert data["message"] == "logged in"
    return response.cookies.get("session_id")


def profile_unlogged() -> None:
    """this method unlogs a user"""
    response = requests.get("http://localhost:5000/profile")
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """this method logs a user in a session"""
    cookies = {
        "session_id": session_id
    }
    response = requests.get("http://localhost:5000/profile", cookies=cookies)
    assert response.status_code == 200


def log_out(session_id: str) -> None:
    """this method logs out a user in a session"""
    cookies = {
        "session_id": session_id
    }
    response = requests.delete("http://localhost:5000/sessions",
                               cookies=cookies, allow_redirects=False)
    # print(response.status_code)
    assert response.status_code in {301, 302, 303, 307, 308}
    assert 'Location' in response.headers

    assert response.headers['Location'] == "/"


def reset_password_token(email: str) -> str:
    """this method resets a password token"""
    form_data = {
        "email": email
    }
    response = requests.post("http://localhost:5000/reset_password")
    if response.status_code == 200:
        data = response.json()
        assert data["email"] == email
        return data["reset_token"]
    return None


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """this method updates a user's password'"""
    form_data = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password
    }
    response = requests.put("http://localhost:5000/reset_password",
                            data=form_data)
    if response.status_code == 200:
        data = response.json()
        assert data["email"] == email
        assert data["message"] == "Password updated"


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
