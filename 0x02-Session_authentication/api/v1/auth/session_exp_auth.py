#!/usr/bin/env python3
"""
This class SessionExpAuth that inherits from SessionAuth in
the file api/v1/auth/session_exp_auth.py
"""
import os

from datetime import datetime, timedelta

from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """This class inherits from SessionAuth so it can make
    an Expiration to a certain session"""

    def __init__(self):
        """__init__ method"""
        super().__init__()
        self.session_duration = int(os.getenv('SESSION_DURATION'), 0)

    def create_session(self, user_id=None) -> str:
        """This module creates a new session"""
        new_session = super().create_session(user_id)
        if new_session is None:
            return None
        self.user_id_by_session_id[new_session] = {
            'user_id': user_id,
            'created_at': datetime.now()
        }
        return new_session

    def user_id_for_session_id(self, session_id=None):
        """
        This method returns the user id for a given session dict
        """
        if session_id is None:
            return None
        if session_id not in self.user_id_by_session_id:
            return None
        session_dict = self.user_id_by_session_id.get(session_id)
        if session_dict is None:
            return None
        if self.session_duration <= 0:
            return session_dict.get('user_id')
        created_at = session_dict.get('created_at')
        if created_at is None:
            return None
        now = datetime.now()
        if created_at + timedelta(seconds=self.session_duration) < now:
            return None
        expires_at = session_dict["created_at"] + timedelta(
            seconds=self.session_duration)
        if expires_at < datetime.now():
            return None
        return session_dict.get("user_id", None)
