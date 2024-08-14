#!/usr/bin/env python3
"""DB module
"""
import logging
from typing import Type

from sqlalchemy import create_engine
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session

from user import Base, User

logging.disable(logging.WARNING)


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """this method adds a new user to the database

        Args:
            email (str): The email address of the new user.
            hashed_password (str): The hashed password of the new user.

        Returns:
            User: A User object representing the new user.
        """
        # Create new user
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()
        return new_user

    def find_user_by(self, **arguments) -> User:
        """this method finds a user by email and hashed password"""
        query = self._session.query(User)
        for arg, val in arguments.items():
            try:
                q_attr = getattr(User, arg)
            except AttributeError:
                raise InvalidRequestError()
            query = query.filter(q_attr == val)
        user = query.first()
        if user is None:
            raise NoResultFound()
        return user

    def update_user(self, user_id: int, **args) -> None:
        """this method updates the user"""
        try:
            user = self.find_user_by(id=user_id)
        except NoResultFound:
            raise ValueError()
        for key, value in args.items():
            if hasattr(user, key):
                setattr(user, key, value)
            else:
                raise ValueError
        self._session.commit()
        return None
