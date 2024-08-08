#!/usr/bin/env python3
"""Create a class for session database authentication"""
import uuid
from datetime import datetime, timedelta
from models.user_session import UserSession
from .session_exp_auth import SessionExpAuth


class SessionDbAuth(SessionExpAuth):
    """Session database auth class"""

    def create_session(self, user_id=None) -> str:
        """Create a session id for the given user id"""
        session_id = super().create_session(user_id)

        if isinstance(session_id, str):
            kwargs = {
                'user_id': user_id,
                'session_id': session_id
            }
            user_session = UserSession(**kwargs)
            user_session.save()
            return session_id

    def user_id_for_session_id(self, session_id=None) -> str:
        """return the user id for the given session id"""
        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return None
        current_time = datetime.now()
        time_span = timedelta(seconds=self.session_duration)
        exp_time = sessions[0].created_at + time_span
        if exp_time < current_time:
            return None
        return sessions[0].user_id

    def destroy_session(self, request=None) -> bool:
        """Destroys an authenticated session."""
        session_id = self.session_cookie(request)
        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return False
        if len(sessions) <= 0:
            return False
        sessions[0].remove()
        return True
