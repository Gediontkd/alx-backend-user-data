#!/usr/bin/env python3
"""Create a class to manage the Api auth"""


from flask import request
from typing import List, TypeVar


class Auth():
    """Manages the API Authentication"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
            This function takes a path and a list of
            excluded paths as arguments
            and returns a boolean value.
        """
        if not path:
            return True
        if not excluded_paths:
            return True
        path = path.rstrip("/")
        for excluded_path in excluded_paths:
            if excluded_path.endswith("*") and \
                    path.startswith(excluded_path[:-1]):
                return False
            elif path == excluded_path.rstrip("/"):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Public method for authorization header"""
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Current user"""
        return None
