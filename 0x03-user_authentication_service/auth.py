#!/usr/bin/env python3
""" auth script defines _hash_password method for now """
from bcrypt import hashpw, gensalt, checkpw
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid


def _hash_password(password: str) -> bytes:
    """method to hash a password"""
    bytes = password.encode("utf-8")

    salt = gensalt()

    hash = hashpw(bytes, salt)
    return hash


def _generate_uuid() -> str:
    """ returns a string representation of a new UUID"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """method that registers a new user"""
        hashed_pwd = _hash_password(password)
        try:
            usr = self._db.find_user_by(email=email)
            if usr is not None:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            user = self._db.add_user(email=email, hashed_password=hashed_pwd)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """method that checks if a user is logged in"""
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                return checkpw(password.encode('utf-8'), user.hashed_password)
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """method that creates a new session"""
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                session_id = _generate_uuid()
                # self._db.update_user(user.id, session_id=session_id)
                user.session_id = session_id
                return session_id
        except NoResultFound:
            return None
        return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """method that returns the user from the session"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: str) -> None:
        """method that destroys a session"""
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            return None
        return None

    def get_reset_password_token(self, email: str) -> str:
        """method that generates a reset password token"""
        try:
            user = self._db.find_user_by(email=email)
            user.reset_token = _generate_uuid()
            return user.reset_token
        except NoResultFound:
            raise ValueError()
        return None

    def update_password(self, reset_token: str, password: str) -> None:
        """method that updates a password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError()
        new_hashed_password = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=new_hashed_password,
            reset_token=None,
        )
