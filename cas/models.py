# -*- coding:utf-8 -*-
from __future__ import unicode_literals

from six.moves.urllib_parse import urlparse
from importlib import import_module
import logging

import redis
from django.conf import settings
from django.db import models
# Ed Crewe - add in signals to delete old tickets
# Single Sign Out
from django.contrib.auth import BACKEND_SESSION_KEY
from django.contrib.auth.signals import user_logged_out, user_logged_in
from django.dispatch import receiver

logger = logging.getLogger('cas')

session_engine = import_module(settings.SESSION_ENGINE)
SessionStore = session_engine.SessionStore

url = urlparse(settings.REDIS_HOST)
db = url.path.strip('/') or 1
host = url.netloc.split(':')[0]  # redis://10.100.196.104:6379/1
port = url.netloc.split(':')[-1]
port = port.isdigit() and port or '6379'
pool = redis.ConnectionPool(host=host, port=port, db=db)


def _get_cas_backend():
    from .backends import CASBackend
    return '{0.__module__}.{0.__name__}'.format(CASBackend)


cas_backend = _get_cas_backend()


class PgtIOU(models.Model):
    """ Proxy granting ticket and IOU """
    pgtIou = models.CharField(max_length=255)
    tgt = models.CharField(max_length=255)
    created = models.DateTimeField(auto_now=True)


class SessionServiceTicket(object):
    r = redis.Redis(connection_pool=pool)

    service_ticket = ''
    session_key = ''
    user = 0

    def __init__(self, user=None, service_ticket=None, session_key=None):
        if user:
            self.user = user
        if service_ticket:
            self.service_ticket = service_ticket
        if session_key:
            self.session_key = session_key

    @property
    def pk(self):
        key = ':'.join((self.__class__.__name__, self.user))
        return key

    @classmethod
    def create(cls, user=None, service_ticket=None, session_key=None):
        data = dict(
            user=user, session_key=session_key, service_ticket=service_ticket)
        obj = cls(**data)
        try:
            cls.r.hmset(obj.pk, data)
        except Exception:
            from traceback import format_exc
            logger.error(format_exc())
            pass
        return obj

    @classmethod
    def get_by_id(cls, key):
        key = ':'.join((cls.__name__, key))
        try:
            data = cls.r.hgetall(key)
        except Exception:
            from traceback import format_exc
            logger.error(format_exc())
            return None
        return cls(**data)

    def delete(self):
        key = ':'.join((self.__class__.__name__, self.service_ticket))
        try:
            self.r.delete(key)
        except Exception:
            from traceback import format_exc
            logger.error(format_exc())
        return self

    def get_session(self):
        """ Searches the session in store and returns it """
        sst = SessionStore(session_key=self.session_key)
        sst[BACKEND_SESSION_KEY] = cas_backend
        return sst

    def __str__(self):
        return '<{}: {}>'.format(self.user, self.service_ticket)

    __repr__ = __str__


def _is_cas_backend(session):
    """ Checks if the auth backend is CASBackend """
    if session:
        backend = session.get(BACKEND_SESSION_KEY)
        return backend == cas_backend
    return None


@receiver(user_logged_in)
def map_service_ticket(sender, **kwargs):

    request = kwargs['request']
    ticket = request.GET.get('ticket')
    if ticket and _is_cas_backend(request.session):
        session_key = request.session.session_key
        sst = SessionServiceTicket.create(
            service_ticket=ticket,
            user=request.user.email,
            session_key=session_key)
        sst.r.expire(sst.pk, 60 * 60 * 24 * 2)


@receiver(user_logged_out)
def delete_service_ticket(sender, **kwargs):
    """ Deletes the mapping between session key and service ticket after user
        logged out """
    request = kwargs['request']
    if _is_cas_backend(request.session):
        email = request.user.email
        sst = SessionServiceTicket.get_by_id(email)
        sst and sst.delete()
