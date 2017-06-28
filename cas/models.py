# -*- coding:utf-8 -*-

from six.moves.urllib_parse import urlencode, urljoin
from six.moves.urllib.request import urlopen

try:
    from xml.etree import ElementTree
except ImportError:
    from elementtree import ElementTree
# from six import urllib

from django.conf import settings
from .exceptions import CasTicketException, CasConfigException
# Ed Crewe - add in signals to delete old tickets
# Single Sign Out
from django.contrib.auth import BACKEND_SESSION_KEY
from django.contrib.auth.signals import user_logged_out, user_logged_in
from django.dispatch import receiver
from redisco import models
from importlib import import_module

session_engine = import_module(settings.SESSION_ENGINE)
SessionStore = session_engine.SessionStore


def _get_cas_backend():
    from .backends import CASBackend
    return '{0.__module__}.{0.__name__}'.format(CASBackend)


cas_backend = _get_cas_backend()


class Tgt(models.Model):
    username = models.CharField(unique=True)
    tgt = models.CharField()

    def get_proxy_ticket_for(self, service):
        """Verifies CAS 2.0+ XML-based authentication ticket.

        Returns username on success and None on failure.
        """
        if not settings.CAS_PROXY_CALLBACK:
            raise CasConfigException("No proxy callback set in settings")

        params = {'pgt': self.tgt, 'targetService': service}

        url = (urljoin(settings.CAS_SERVER_URL, 'proxy') + '?' +
               urlencode(params))

        page = urlopen(url)

        try:
            response = page.read()
            tree = ElementTree.fromstring(response)
            if tree[0].tag.endswith('proxySuccess'):
                return tree[0][0].text
            else:
                raise CasTicketException("Failed to get proxy ticket")
        finally:
            page.close()


class PgtIOU(models.Model):
    """ Proxy granting ticket and IOU """
    pgtIou = models.CharField(unique=True)
    tgt = models.CharField()
    created = models.DateTimeField(auto_now=True)


def get_tgt_for(user):
    if not settings.CAS_PROXY_CALLBACK:
        raise CasConfigException("No proxy callback set in settings")

    tgt = Tgt.objects.filter(username=user.username).first()
    if not tgt:
        raise CasTicketException("no ticket found for user " + user.username)


# def delete_old_tickets(**kwargs):
# """ Delete tickets if they are over 2 days old
# kwargs = ['raw', 'signal', 'instance', 'sender', 'created']
# """
# sender = kwargs.get('sender', None)
# now = datetime.now()
# expire = datetime(now.year, now.month, now.day - 2)
# sender.objects.filter(created__lt=expire).delete()

#TODO
# post_save.connect(delete_old_tickets, sender=PgtIOU)


class SessionServiceTicket(models.Model):
    service_ticket = models.CharField(
        'service ticket', required=True, unique=True)
    session_key = models.CharField('session key')
    user = models.IntegerField()

    def __str__(self):
        return self.service_ticket

    __repr__ = __str__

    def get_session(self):
        """ Searches the session in store and returns it """
        sst = SessionStore(session_key=self.session_key)
        sst[BACKEND_SESSION_KEY] = cas_backend
        return sst


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
        SessionServiceTicket.objects.create(
            service_ticket=ticket,
            user=request.user.id,
            session_key=session_key)


@receiver(user_logged_out)
def delete_service_ticket(sender, **kwargs):
    """ Deletes the mapping between session key and service ticket after user
        logged out """
    request = kwargs['request']
    if _is_cas_backend(request.session):
        session_key = request.session.session_key
        sst = SessionServiceTicket.objects.filter(
            session_key=session_key).first()
        sst and sst.delete()

