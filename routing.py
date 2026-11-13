"""Validated, offline VLESS import. Never logs credentials."""
import copy
import ipaddress
import re
import uuid
from urllib.parse import urlsplit, parse_qs, unquote


def parse_vless(uri):
    try:
        parsed = urlsplit(uri.strip())
        if parsed.scheme != 'vless' or not parsed.hostname or not parsed.username or parsed.password:
            raise ValueError()
        ident = str(uuid.UUID(unquote(parsed.username)))
        port = parsed.port
        if port is None or not 1 <= port <= 65535: raise ValueError()
        host = parsed.hostname
        try: ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in host.split('.')): raise ValueError()
        fields = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        if any(len(v) != 1 for v in fields.values()): raise ValueError()
        q = {k:v[0] for k,v in fields.items()}
        allowed = {'security','type','sni','pbk','sid','fp','flow','encryption','serviceName','path','host','alpn','spx','mode'}
        unknown = set(q)-allowed
        if unknown: raise ValueError('Неподдерживаемые параметры: '+', '.join(sorted(unknown)))
        security = q.get('security','none'); transport = q.get('type','tcp')
        if security not in ('none','tls','reality') or transport not in ('tcp','ws','grpc'): raise ValueError()
        if q.get('encryption','none') != 'none': raise ValueError()
        flow = q.get('flow','')
        if flow not in ('','xtls-rprx-vision'): raise ValueError()
        if flow and (transport != 'tcp' or security not in ('tls','reality')): raise ValueError()
        stream = {'network':transport, 'security':security}
        if security in ('tls','reality'):
            sni = q.get('sni','')
            if not sni or not re.fullmatch(r'[A-Za-z0-9.-]+',sni): raise ValueError()
            settings = {'serverName':sni, 'fingerprint':q.get('fp','chrome')}
            if security == 'reality':
                if not re.fullmatch(r'[A-Za-z0-9_-]{43}',q.get('pbk','')): raise ValueError()
                sid = q.get('sid','')
                if len(sid)%2 or not re.fullmatch(r'[0-9a-fA-F]{0,16}',sid): raise ValueError()
                settings.update(publicKey=q['pbk'],shortId=sid,spiderX=q.get('spx','/'))
            elif q.get('alpn'): settings['alpn']=q['alpn'].split(',')
            stream[security+'Settings']=settings
        if transport == 'ws': stream['wsSettings']={'path':q.get('path','/'),'headers':{'Host':q.get('host',host)}}
        if transport == 'grpc':
            if q.get('mode','gun') not in ('gun','multi'): raise ValueError()
            stream['grpcSettings']={'serviceName':q.get('serviceName',''),'multiMode':q.get('mode')=='multi'}
        user = {'id':ident,'encryption':'none'}
        if flow: user['flow']=flow
        return {'tag':'to-eu','protocol':'vless','settings':{'vnext':[{'address':host,'port':port,'users':[user]}]},'streamSettings':stream}
    except (ValueError,AttributeError):
        # Do not echo the URI or exception details: they may contain secrets.
        raise ValueError('Некорректная или неподдерживаемая VLESS-ссылка.') from None


def cascade(config, outbound, inbound_tags, mode='ru-direct-eu'):
    if mode not in ('ru-direct-eu','all-eu'): raise ValueError('Неизвестный шаблон.')
    known = {i.get('tag') for i in config.get('inbounds',[])}
    if not inbound_tags or not set(inbound_tags) <= known: raise ValueError('Укажите существующие inbound.')
    result = copy.deepcopy(config)
    outbounds=result.setdefault('outbounds',[])
    if any(o.get('tag') in ('to-eu','vps-manager-direct') for o in outbounds):
        raise ValueError('Теги уже существуют; требуется явное согласование существующего каскада.')
    outbounds.extend([copy.deepcopy(outbound),{'tag':'vps-manager-direct','protocol':'freedom'}])
    routing=result.setdefault('routing',{})
    rules=[]
    if mode=='ru-direct-eu':
        rules += [{'type':'field','inboundTag':inbound_tags,'domain':['domain:ru','domain:su','domain:xn--p1ai'],'outboundTag':'vps-manager-direct'}, {'type':'field','inboundTag':inbound_tags,'ip':['geoip:ru'],'outboundTag':'vps-manager-direct'}]
    rules.append({'type':'field','inboundTag':inbound_tags,'outboundTag':'to-eu'})
    # Existing policy remains first, including block rules. Operator reviews precedence.
    routing['rules']=routing.get('rules',[])+rules
    return result
