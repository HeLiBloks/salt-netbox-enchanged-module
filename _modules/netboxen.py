# -*- coding: UTF-8 -*-

# :maintainer:    Henrik Lindgren <henrikprojekt at gmail.com>,
# :maturity:      new
# :depends:
# :platform:      most

from __future__ import absolute_import, unicode_literals, print_function

# Import Python libs
import logging

# Import salt libs
import salt.utils.http
import salt.utils.json
from salt.exceptions import CommandExecutionError

# Import 3rd-party libs
from salt.ext import six

log = logging.getLogger(__name__)

try:
    import socket
    import random
    import re
    HAS_LIB = True
except ImportError as e:
    HAS_LIB = False
    log.error('[netboxen]: {0} lib not found'.format(str(e)))


def __virtual__():
    '''
    must be installed.
    '''
    if HAS_LIB:
        return HAS_LIB
    return False


CONFIG = {}


def __init__(opts):
    """
    Assigns netbox api configuration to `CONFIG` variable
    The configuration is looked up in the following order
        pillar, opts, grains
    :returns: True
    TODO: salt-ssh cant handle config added this way
    """
    global CONFIG
    CONFIG = __pillar__.get('netbox', opts.get('netbox', __grains__.get('netbox')))
    if isinstance(CONFIG, type(None)) or not isinstance(CONFIG.get('token'), six.string_types):
        raise salt.exceptions.SaltInvocationError(
            'netbox token not found! Set pillar, config or grains to:\n'
            'netbox.token: 72830d67beff4ae178b94d8f781842408df8069d'
        )
    CONFIG['token'] = 'Authorization: Token {0}'.format(CONFIG.get('token'))


def _system_name():
    """
    returns pillar-name or minion_id
    :returns:
    """
    if CONFIG.get('name'):
        return CONFIG['name']
    return __grains__.get('id')


def _name_int(name, kwargs=None):
    """
    assign name to id if name is an int
    else assign name to kwargs['name']
    """
    if isinstance(name, six.string_types):
        kwargs['name'] = name
    elif isinstance(name, int) and kwargs.get('id') is None:
        kwargs['id'] = name
    return _clean_kwargs(kwargs)


def _result(result):
    """
    Unpack results from salt.utils.http.query() call
    :result: dictionary as returned from netbox-api
    :returns: list of dicts,
              single dict for single result,
              `{}` for empty result
    """
    # DEBUG:
    # check if returned object was decoded correctly
    if isinstance(result, dict):
        # check if dict['results'] contains multiple items
        dict_ = result.get('dict', {})
        if dict_.get('count') and dict_.get('count') > 1:
            return dict_.get('results')
        elif dict_.get('count') == 0:
            return []
        elif dict_.get('count') == 1:
            return dict_.get('results')[0]
        elif dict_.get('id'):
            # TODO: document this?
            return dict_
    status = result.get('status')

    if int(status) > 404:
        return (False, result)
    elif status == 204:
        # DELETE succeded no content is returned
        # log.trace(msg='[netboxen] returned: {0}'.format(result))
        return result
    elif status >= 400:
        return (False, result)
    return result


def _slugify(name=None):
    """
    slug encode slug
    :slug:
    :returns: slugified name
    """
    if not isinstance(name, six.string_types):
        log.debug(msg='[netboxen] func: {} attempt to slugify wrong type'.format(name))
        return None
    return re.sub(r'[\W\s-]', '_', name).strip().lower()


def _clean_kwargs(arg):
    """
    removes __ keys and None keys from a dictionary
    returns: dict
    """
    clean = __utils__['args.clean_kwargs'](**arg)
    clear = {k: v for k, v in clean.items() if v is not None}
    return clear


def _mask2cidr(ip, netmask):
    """
    :ip: eg. 1.2.3.4
    :netmask: eg. 255.255.255.0
    :returns: cidr, eg. 24
    see https://stackoverflow.com/questions/38085571/how-use-netaddr-to-convert-subnet-mask-to-cidr-in-python
    """
    ip_mask = str(sum(bin(int(x)).count('1') for x in netmask.split('.')))
    return '{0}/{1}'.format(ip, ip_mask)


def _has_dict(_item, key=None, deffunc=None, **defkwargs):
    """
    _get() functions return dict, list or None
    This function returns an object of correct type to be consumed
    by the calling function.
    :_item: item to determine type of
    :key: key to return from dict if `item` is dict
    :default: default to return if item is not a dict
    :returns: dict[key] or None
    """
    #  (kwargs.get('__pub_fun'))
    #  if isinstance(_item, type(None)) and kwargs.get('__pub_fun').endswith('_add') :
    #  return None
    if isinstance(_item, (list, type(None))) and deffunc and key:
        return deffunc(**defkwargs).get(key)
    elif isinstance(_item, dict) and key:
        return _item.get(key)
    elif isinstance(_item, dict):
        return _item
    return None


def _left_join(dict1, dict2):
    """
    Remove None keys from dicts, overwrite keys in dict1,
    with keys from dict2
    :dict1: overwrite duplicate keys in this dict
    :dict2:
    :returns: dict
    """
    # TODO: use __utils__['dict..'] instead
    dict1 = {k: v for k, v in dict1.items() if v is not None and v != ''}
    dict1.update({k: v for k, v in dict2.items() if v is not None and v != ''})
    return dict1


def filter_(app='dcim', endpoint='devices', filter=None, method='GET', **kwargs):
    """
    return objects from a netbox filter expression
    :name: object name to filter on
    :app:
    :endpoint: app endpoint
    :filter: string to filter on '?name__nie=string1&id__n=7'
    :**kwargs: key value pairs to filter on

    suffix the key with a lookup expression:
       __n     :  not equal (negation)
       __ic    :  case insensitive contains
       __nic   :  negated case insensitive contains
       __isw   :  case insensitive starts with
       __nisw  :  negated case insensitive starts with
       __iew   :  case insensitive ends with
       __niew  :  negated case insensitive ends with
       __ie    :  case sensitive exact match
       __nie   :  negated case sensitive exact match
    numeric expressions:
       __n     :  not equal (negation)
       __lt    :  less than
       __lte   :  less than or equal
       __gt    :  greater than
       __gte   :  greater than or equal
    """
    http_args = {'decode': True,
                 'decode_type': 'json',
                 'status': True,
                 'headers': True,
                 'method': method}
    http_args['header_list'] = [
        CONFIG.get('token'),
        'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
        'Accept: application/json'
    ]
    http_args['url'] = '{0}{1}/{2}/'.format(CONFIG.get('url'),
                                            app,
                                            endpoint)

    kwargs = _clean_kwargs(kwargs)
    if filter is None and len(kwargs.items()) != 0:
        http_args['params'] = kwargs
    elif filter:
        http_args['url'] = '{0}?{1}'.format(http_args['url'], filter)

    http_args['opts'] = __opts__
    # DEBUG
    #  log.error('_filter: http.query: {0}'.format(http_args))
    query = salt.utils.http.query(**http_args)
    return _result(query)


def method_(app='dcim', method='GET', endpoint='devices', **kwargs):
    '''
    GET, POST, PATCH, OPTIONS,, DELETE, PUT NetBox.
    app
        String of netbox app, e.g., ``dcim``, ``circuits``, ``ipam``,
        ``virtualization``, ``_choices``
    endpoint
        String of app endpoint, e.g., ``sites``, ``regions``, ``devices``,
        ``virtual-machines``, ``interfaces``
    method
        ``GET``, ``POST``, ``PATCH``, ``DELETE``, ``PUT``
    **kwargs
        key, values to send, e.g. ``name``, ``id``, ``...``
    '''
    #  CONFIG = _config()
    data = _clean_kwargs(kwargs)
    header = [CONFIG['token'],
              'Content-Type: application/json',
              'Accept-Encoding: utf-8',
              'Accept: application/json']
    http_args = {
        'method': method,
        'header_list': header,
        'decode': True,
        'status': True,
        'decode_type': 'json'}

    http_args['url'] = CONFIG['url']
    for item in [app, endpoint, data.pop('id', None)]:
        if item and len(str(item)) > 0 and item != '':
            http_args['url'] = http_args['url'] + str(item) + '/'

    _id = None
    if method in ('GET', 'DELETE') and (data.get('name') or data.get('slug') or 'model' in data)\
            and data.get('id') is None:
        if method in ('GET', 'DELETE') and data.get('slug') is None:
            # if we only have data['name'] or data['model'], get id
            try:
                _name = {}
                if data.get('name'):
                    _name.update({'name': data['name']})
                elif data.get('model'):
                    _name.update({'model': data['model']})
                _id = filter_(kwargs=_name,
                              app=app,
                              endpoint=endpoint).get('id')
                assert isinstance(_id, int)
            except Exception as e:
                # throw exception if list is returned
                log.debug(
                    msg='[netboxen] filter_() did not return id instead: {0}'.format(str(e)))
        # if we only have data['slug']
        elif isinstance(data.get('slug'), six.string_types) and data.get('name') is None:
            _id = filter_(slug=data['slug'],
                          app=app,
                          endpoint=endpoint).get('id')

    # append _id to url
        if isinstance(_id, int):
            http_args['url'] += str(_id) + '/'
    elif data.get('id'):
        _id = data.pop('id')
    # TODO: add method=DELETE
    http_args['data'] = salt.utils.json.dumps(data)
    req = salt.utils.http.query(**http_args)
    return _result(req)


def _keep_id_name(arg):
    """
    return: dict id containing id and name keys
    """
    idname = {}
    idname.setdefault('id', arg.get('id'))
    idname.setdefault('name', arg.get('name'))
    return idname


def _is_virtual():
    """
    Check if minion is a virtual-machine, physical-machine, hypervisor in dom0 or hypervisor
    :name: minion_id or hostname, defaults to minions hostname
    :returns: dict with following keys,
        { "virtual": 'xen', "dom0": bool}
    """
    virtual_ = {}
    if __grains__.get('salt-cloud') or __grains__.get('virtual') != 'physical':
        virtual_['virtual'] = __grains__.get('virtual')
    if 'dom0' in __grains__.get('virtual_subtype', '').lower():
        virtual_['virtual'] = 'physical'
        virtual_['dom0'] = True
    else:
        virtual_['virtual'] = __grains__.get('virtual')
    return virtual_


def introspect_(name=None, **kwargs):
    """
    return introspected object for current minion of given attribute
    this function makes no changes to netbox or minion
    name: str, object to introspect one of
        device
        device-type
        vm
        manufacturer
        platform
        cluster
        interfaces
        ip-addresses
        ip-addresses6
    _id: bool, wheter do return id of object or its name
    :returns: dict of introspected object or list of objects
    """
    # set defaults from config in pillar, minion config, grains
    if 'defaults' not in locals():
        defaults = {}
        for config in ['pillar.get', 'config.get', 'grains.get']:
            defaults.update(__salt__[config]('netbox'))

    # default to returning string instead of id for objects if called from cli
    if kwargs.get('__pub_fun', 'null').endswith('_add'):
        _name = 'name'
    else:
        _name = 'id'

    if name in ('vlan', 'vlans'):
        if __salt__.get('lldp.interfaces'):
            vlans = __salt__['lldp.interfaces']()
        return vlans

    if name in ['manufacturer', 'manufacturers']:
        manufacturer = __grains__.get('manufacturer')
        return {
            'id': _has_dict(manufacturer_get(manufacturer), 'id'),
            'name': manufacturer,
            'slug': _slugify(manufacturer),
            'description': None}

    if name in ['platform', 'platforms']:
        platform = __grains__.get('lsb_distrib_codename',
                                  __grains__.get('osfullname',
                                                 __grains__.get('osfinger')))
        # os-manufacturer conflicts with devices hardware-manufacturer
        # manufacturer = _has_dict(introspect_('manufacturer'), 'id')
        return {
            'id': _has_dict(platform_get(platform), 'id'),
            'name': platform,
            'slug': _slugify(platform),
            'manufacturer': None,
            'description': None,
            'napalm_driver': None,
            'napalm_args': None
        }
    if name in ('available-ips'):
        ips = {'prefix': '',
               'site': 0,
               'vrf': 0,
               'tenant': 1,
               #  'vlan': ${_vlan},
               'status': 'active',
               'dns_name': '',
               'is_pool': true,
               'description': '',
               'custom_fields': {}
               }
        return ips

    if name in ['role', 'roles']:
        role = 'Server'
        if 'smbios.get' in __salt__ and _is_virtual().get('virtual') == 'virtual':
            # should yield Server, Desktop, Other, ...
            role = __salt__['smbios.get']('chassis-type')
        if not role:
            role = __grains__.get('virtual_hv_version', role)
        if _is_virtual().get('virtual') == 'physical':
            vm_role = True
        else:
            # dissregard nested virtualization for virtual-machines
            vm_role = False
        # Todo: make _randcolor() idemipotent by hashing system attributes
        return {"id": _has_dict(device_role_get(role), 'id'),
                "name": role,
                "slug": _slugify(role),
                "color": _randcolor(),
                "vm_role": vm_role,
                "description": None
                }

    elif name in ('device-types', 'device-type'):
        if 'smbios.records' in __salt__:
            try:
                part_number = __salt__['smbios.records']('1',
                                                         'sku_number')[0].get('data')
                part_number = part_number.get('sku_number')
            except IndexError as e:
                part_number = None
            if __grains__.get('manufacturer') == 'LENOVO':
                product_name = 'version'
            else:
                product_name = 'product_name'
            model = __salt__['smbios.records']('1')[0].get('data',
                                                           {}).get(product_name)
        else:
            # Todo: support for
            part_number = __grains__.get('serialnumber')
            model = __grains__.get('productname')
        manufacturer = introspect_('manufacturer').get(_name)
        return {
            'id': _has_dict(device_type_get(model), 'id'),
            'model': model,
            'slug': _slugify(model),
            'manufacturer': manufacturer,
            'part_number': part_number,
            'u_height': 0,
            'is_full_depth': None,
            'subdevice_role': None,
            'comments': None,
            'tags': None,
            'custom_fields': {}
        }

    elif name in ('cluster-types', 'cluster-type'):
        if _is_virtual().get('virtual') != 'physical':
            return {}
        clustertype = _is_virtual().get('virtual')
        return {
            'id': _has_dict(cluster_type_get(clustertype), 'id'),
            "name": clustertype,
            "slug": _slugify(clustertype),
            "description": None
        }

    elif name in ('site', 'sites'):
        # Todo: grab site from lldp or snmp config
        site = {}
        site['site'] = CONFIG.get('site')
        return {'site': site,
                'id': _has_dict(filter_(app='dcim',
                                        endpoint='sites',
                                        site=site),
                                'id')
                }

    elif name in ('cluster', 'clusters'):
        # Todo: grab site from lldp or snmp config
        site = CONFIG.get('site')
        cluster = CONFIG.get('cluster')
        cluster_group = CONFIG.get('cluster_group')
        tenant = CONFIG.get('tenant')
        cluster = {
            "id": _has_dict(cluster_get(cluster), 'id'),
            "name": cluster,
            "slug": _slugify(cluster),
            "type": _has_dict(introspect_('cluster-type'), _name),
            "group": cluster_group,
            "tenant": tenant,
            "site": site,
            "comments": None,
            "tags": None
        }
        return cluster

    elif name in ('device', 'devices'):
        device = _system_name()
        if 'system.get_computer_desc' in __salt__:
            computer_desc = __salt__['system.get_computer_desc']()
            if not isinstance(computer_desc, six.string_types):
                computer_desc = None
        else:
            computer_desc = None
        if 'smbios.get' in __salt__:
            asset_tag = __salt__['smbios.get']('chassis-asset-tag',
                                               __salt__['smbios.get']('system-asset_tag'))
            serial = __salt__['smbios.get']('chassis-serial-number',
                                            __salt__['smbios.get']('system-serial-number'))
        else:
            asset_tag = __grains__.get('asset_tag')
            serial = __salt__['grains.get']('motherboard:serialnumber')
        # TODO: fix, 'referenced before assignment'
        primary_ip6=None
        if 'lldp.chassis' in __salt__:
            for ip in __salt__['lldp.chassis']().get('mgmt-ip', []):
                for ipm in introspect_('ip-addresses'):
                    if ip in ipm.get('address') and ':' in ip:
                        primary_ip6 = {'address': ipm.get('address')}
                        continue
                    elif ip in ipm.get('address') and '.' in ip:
                        primary_ip4 = {'address': ipm.get('address')}
        else:
            try:
                primary_ip6 = _has_dict(introspect_('ip-addresses6')[0], 'id')
            except IndexError as e:
                primary_ip6 = None
            try:
                primary_ip4 = _has_dict(introspect_('ip-addresses4')[0], 'id')
            except IndexError as e:
                primary_ip4 = None
        return {
            "id": _has_dict(device_get(device), 'id'),
            "name": device,
            "display_name": device,
            "device_type": _has_dict(introspect_('device-types'), _name),
            "device_role": _has_dict(introspect_('role'), _name),
            "platform": _has_dict(introspect_('platform'), _name),
            "serial": serial,
            "asset_tag": asset_tag,
            "site": _has_dict(introspect_('site'), _name),
            "rack": None,
            "position": None,
            "face": None,
            "parent_device": None,
            "status": "active",
            "primary_ip4": primary_ip4,
            "primary_ip6": primary_ip6,
            "tenant": None,
            "cluster": _has_dict(introspect_('cluster'), 'name'),
            "virtual_chassis": None,
            "vc_position": None,
            "vc_priority": None,
            "comments": None,
            "local_context_data": None,
            "tags": None,
            "custom_fields": None,
            "config_context": None,
            "description": computer_desc
        }

    if name in ['vm', 'virtual-machine']:
        vm_name = _system_name()
        if 'status.meminfo' in __salt__:
            memory = __salt__['status.meminfo']().get('MemTotal',
                                                      {}).get('value', 1)
            try:
                memory = int(float(int(memory) / 1000))
            except Exception as e:
                log.error(msg='[netboxen]: memory {0}'.format(str(e)))
                memory = None
        else:
            memory = None
        if 'system.get_computer_desc' in __salt__:
            comments = __salt__['system.get_computer_desc']()
        else:
            comments = None
        vcpus = __grains__.get('num_cpus')
        # TODO: Add disk function
        try:
            primary_ip6 = _has_dict(introspect_('ip-addresses6')[0], 'id')
        except IndexError as e:
            primary_ip6 = None
        try:
            primary_ip4 = _has_dict(introspect_('ip-addresses4')[0], 'id')
        except IndexError as e:
            primary_ip4 = None
        return {
            "id": _has_dict(vm_get(vm_name), 'id'),
            "name": vm_name,
            "vcpus": vcpus,
            "memory": memory,
            "status": "active",
            "site": _has_dict(introspect_('site'), _name),
            "cluster": _has_dict(introspect_('cluster'), _name),
            "role": _has_dict(introspect_('role'), _name),
            "tenant": None,
            "platform": _has_dict(introspect_('platform'), _name),
            "primary_ip4": primary_ip4,
            "primary_ip6": primary_ip6,
            "disk": _disksize(),
            "comments": comments,
            "local_context_data": None,
            "tags": None,
            "custom_fields": None,
            "config_context": None
        }

    if name in ('ip-addresses', 'ip-addresses4', 'ip-addresses6','ips'):
        if _is_virtual().get('virtual') == 'physical':
            device_vm = {'device': _system_name()}
        else:
            device_vm = {'virtual_machine': _system_name()}
        nb_ips = ipaddress_get(**device_vm)
        if isinstance(nb_ips, (dict, type(None))):
            nb_ips = [nb_ips]
        nb_ips = {item['address']: item for item in nb_ips
                  if isinstance(nb_ips[0],
                                dict)}
        minion_iface = introspect_('interfaces')
        if name[-1] == '6':
            ipv = 'nope'
        else:
            ipv = 'inet'
        _ips = []
        for iface_name, iface in __salt__['network.interfaces']().items():
            if iface_name in ('lo', 'lo0') or 'Software Loopback Interface' in iface_name:
                continue
            for ip in iface.get(ipv, []) + iface.get('inet6', []):
                if '.' in ip.get('address', ''):
                    ip_cidr = _mask2cidr(ip.get('address'), ip.get('netmask'))
                    label = ip.get('label')
                    family = 4
                elif ':' in ip.get('address', ''):
                    ip_cidr = '{0}/{1}'.format(ip.get('address'), ip.get('prefixlen'))
                    family = 6
                else:
                    continue
                if iface.get('up'):
                    up='active'
                else:
                    up=None
                _ips.append({
                    'id': _has_dict(nb_ips.get(ip_cidr), 'id'),
                    'family': family,
                    'address': ip_cidr,
                    'vrf': None,
                    'tenant': None,
                    'status': up,
                    'role': None,
                    'interface': minion_iface.get(iface_name, {}).get('id'),
                    'nat_inside': None,
                    'nat_outside': None,
                    'dns_name': _ptr_lookup(ip.get('address')),
                    'description': None,
                })
        return _ips

    if name in ('prefixes', 'prefix'):
        subnets = []
        sub6 = __salt__['network.subnets6']()
        sub4 = __salt__['network.subnets']()
        if sub6 and sub4:
            sub4 += sub6
        elif sub6:
            sub4 = sub6
        for subnet in sub4:
            if ':' in subnet:
                family = 6
            else:
                family = 4
            subnets.append({
                "family": family,
                "id": 1,
                "is_pool": True,
                "prefix": subnet,
                "description": "",
                "status": { "value":"active" },
                "vrf": None,
                # "site": None,
                # "tenant": None,
                # "vlan": None,
                # "role": None,
            })
        return subnets

    if name in ('interfaces', 'interface'):
        if _is_virtual().get('virtual') == 'physical':
            dev_type = {'device': _has_dict(device_get(
                _system_name()),
                'id')}
            nb_interfaces = interface_get(device=_system_name())
            nic_type = 'other'
        else:
            dev_type = {'virtual_machine': _has_dict(vm_get(
                _system_name()),
                'id')}
            nb_interfaces = interface_get(vm=_system_name())
            nic_type = 'virtual'
        # unpack list to dict { "nic_name": { "key":"val" } }
        nb_interfaces = {item['name']: item
                         for item in nb_interfaces
                         if isinstance(nb_interfaces, list)}
        interfaces = {}
        vlanid = re.compile(r'\.[1-9]\d*$')

        for iname, iface in __salt__['network.interfaces']().items():
            if iname in ('lo', 'lo0') or 'Software Loopback Interface' in iname:
                continue
            t_vlans = None
            if 'device' in dev_type.keys():
                nic_type = 'other'
                if iface.get('mac_address', 'x1')[1].lower() in '26ae':
                    # persume device is virtual if its mac is localy assigned
                    nic_type = 'virtual'
            #  elif 'Wireless LAN' in iname:
                #  nic_type=''
            if iface.get('up'):
                up='active'
            else:
                up=None
            if re.search(vlanid, iname):
                t_vlans = [{'vid': iname.split('.')[-1]}]
                nic_type = 'virtual'
            interfaces[iname] = {
                "id": nb_interfaces.get(iname, {}).get('id'),
                "name": iname,
                "type": nic_type,
                "enabled": iface.get('up'),
                "lag": None,
                "mtu": None,
                "mac_address": iface.get('hwaddr'),
                "mgmt_only": None,
                "description": iface.get('label'),
                "cable": None,
                "mode": None,
                "untagged_vlan": None,
                "tagged_vlans": t_vlans}
            interfaces[iname].update(dev_type)
        return interfaces


def _ptr_lookup(ip_addr):
    """
    lookup ip address
    :ip: ip address
    :returns: dns record as string or None
    """
    if not ip_addr:
        return None
    #  record = __utils__['network.ip_to_host'](ip_addr)
    try:
        record = socket.gethostbyaddr(ip_addr)
    except Exception as e:
        log.trace('[netboxen] could not lookup: {0}'.format(e))
        record = []
    return next(iter(record or []), '')


def vlan_get(name=None, **kwargs):
    """
    vid: int between 1-4094
    name: str, vlan name
    id: int, ID
    display_name: str, vlan name
    site: string,
    group: str, vlan group
    tenant: str,
    role: int, None
    tags:
    description: str, None
    method: one of POST PUT PATCH, OPTIONS, DELETE, HEAD
    return: list None or dict
    """
    if isinstance(name, int):
        kwargs.setdefault('vid', name)
    else:
        kwargs.setdefault('name', name)
    kwargs = _clean_kwargs(kwargs)
    return filter_(app='ipam',
                   endpoint='vlans',
                   method=kwargs.pop('method', 'GET'),
                   **kwargs)


def vlan_add(name=None, introspect=False, **kwargs):
    """
    vid: int between 1-4094
    name: str, vlan name
    id: int, ID
    display_name: str, vlan name
    site: string,
    group: str,
    tenant: str,
    role: int, None
    tags:
    description: str, None
    method: one of POST PUT PATCH, OPTIONS, DELETE, HEAD
    return: list None or dict
    """
    if isinstance(name, int):
        kwargs.setdefault('vid', name)
    elif isinstance(name, six.string_types):
        kwargs.setdefault('name', name)
    if introspect:
        kwargs = _left_join(introspect_('vlan'), kwargs)
    kwargs = _clean_kwargs(kwargs)
    return filter_(app='ipam',
                   endpoint='vlans',
                   method=kwargs.pop('method', 'GET'),
                   **kwargs)


def ipaddress_get(name=None, **kwargs):
    """
    name: ip-address or its id
    id: int, None
    device: device name
    family: int, 4 or 6
    vrf: None,
    tenant: None,
    status: 1,
    role: int, None
    interface: interface name
    nat_inside: int, None
    nat_outside: int, None
    dns_name: str, None
    description: str, None
    method: one of POST PUT PATCH, OPTIONS, DELETE, HEAD
    return: list None or dict
    """
    # TODO: fix!!! __pub_fun
    if kwargs.get('__pub_fun') and isinstance(name, type(None)) and len(
            _clean_kwargs(kwargs)) == 0:
        return None
    kwargs.setdefault('address', name)
    return filter_(app='ipam',
                   endpoint='ip-addresses',
                   method=kwargs.pop('method', 'GET'),
                   **kwargs)


def manufacturer_get(name=None, **kwargs):
    """
    name: Name of manufacturer
    """
    kwargs = _name_int(name=name, kwargs=kwargs)
    kwargs = _clean_kwargs(kwargs)
    return filter_(app='dcim',
                   method=kwargs.pop('method', 'GET'),
                   endpoint='manufacturers',
                   **kwargs)


def manufacturer_add(name=None, introspect=False, **kwargs):
    """
    Add a manufacturer
    :name: Name of manufacturer
    :slug: slug used by netbox
    :description: ...
    :method: one of POST PUT PATCH, OPTIONS, DELETE

    CLI Example:
    .. code-block:: bash
        salt '*' netboxen.manufacturer name=rheinmetall slug=None
    """
    kwargs = _clean_kwargs(kwargs)
    if name:
        kwargs['name'] = name
        kwargs['slug'] = _slugify(name)
    if not name and introspect:
        kwargs = _left_join(introspect_('manufacturer'), kwargs)
    return method_(app='dcim',
                   method=kwargs.pop('method', 'POST'),
                   endpoint='manufacturers',
                   **kwargs)


def platform_get(name=None, **kwargs):
    """
    :name: Name of platform
    CLI Example:
    .. code-block:: bash
        salt 'f-st' netboxen.platform_get name=atari
    """
    kwargs = _name_int(name, kwargs=kwargs)
    kwargs = _clean_kwargs(kwargs)
    return filter_('dcim',
                   'platforms',
                   method=kwargs.pop('method', 'GET'),
                   **kwargs)


def platform_add(name=None, introspect=False, **kwargs):
    '''
    required, unless introspect is True
        name: Name of platform,
    slug: slug used by netbox
    manufacturer: string
    napalm_driver: string
    napalm_args: string
    description: string
    returns:
    CLI Example:
    .. code-block:: bash
        salt '*' netboxen.platform Death_Star slug=dstar napalm_driver=X11 \
        napalm_args='-beam'
    '''
    if isinstance(name, six.string_types):
        kwargs.setdefault('name', name)
        kwargs.setdefault('slug', _slugify(name))
    if introspect:
        # override introspected keys with those passed to function
        kwargs = _left_join(introspect_('platform'), kwargs)
    kwargs = _clean_kwargs(kwargs)
    if isinstance(kwargs.get('manufacturer'), six.string_types):
        kwargs['manufacturer'] = _has_dict(manufacturer_get(kwargs['manufacturer']),
                                           'id',
                                           manufacturer_add,
                                           name=kwargs['manufacturer'],
                                           introspect=introspect)
    return method_(app='dcim',
                   endpoint='platforms',
                   method=kwargs.pop('method', 'POST'),
                   **kwargs)


def interface_get(name=None, device=None, vm=None, **kwargs):
    '''
    Get interfaces from devices and virtual-machines in netbox
    name: Name of interface
    vm: vm name, or `True` to only list vm interfaces
    device: device name or True
    returns: interface or list of interfaces
    '''

    if kwargs and kwargs.get('__pub_fun').endswith(('_add', 'spect')) and isinstance(
        name,
        type(None)) and len(
            _clean_kwargs(kwargs)) == 0:
        return None
    app = 'dcim'
    if isinstance(vm, (six.string_types, int, type(True))):
        app = 'virtualization'
        if isinstance(vm, six.string_types):
            kwargs.setdefault('virtual_machine', vm)
        elif isinstance(vm, int):
            kwargs.setdefault('virtual_machine_id', vm)
    elif isinstance(vm, type(False)):
        app = 'dcim'
    if isinstance(device, (str, int)):
        app = 'dcim'
        if isinstance(device, int):
            kwargs.setdefault('device_id', device)
        else:
            kwargs.setdefault('device', device)
    kwargs = _clean_kwargs(kwargs)
    # DEBUG
    # log.error(app+': interfaces_get: '+str(kwargs))
    return filter_(app=app,
                   endpoint='interfaces',
                   method=kwargs.pop('method', 'GET'),
                   **kwargs)


def interface_add(name=None, vm=None, device=None, introspect=False, **kwargs):
    """
    Adds interface to netbox
    Arguments required, unless introspect is True
        name: Name of interface to create, eth0, wlan0, ...
        device: Name of parent device
    mac_address:
    enabled: bool
    type: type of interface, `virtual`,...
    mode: vlan mode
    vm: Name or id of parent virtual-machine
    introspect: grab interfaces from current minion
    method: one of POST PUT PATCH, OPTIONS, DELETE
    .. code-block:: bash
        salt '*' netboxen.interface_add vm=v-machine-l02  name=eth0  type='virtual'\
            enabled=True mtu=1500  mac_address='20:12:10:20:2A:11' \
            mgmt_only=False  description='new interface' mode=access tags=tb2
    """
    if device is None and vm is None and introspect is False:
        return False

    kwargs = _name_int(name, _clean_kwargs(kwargs))
    if isinstance(device, (str, int)):
        if isinstance(device, six.string_types):
            device = _has_dict(device_get(device), 'id')
        kwargs['device'] = device
        if not kwargs['virtual_machine']:
            log.error('[netboxen]: could not find id for device: {0}'.format(device))
            return False
    elif device is None and isinstance(vm, (str, int)):
        app = 'virtual-machines'
        kwargs['virtual_machine'] = _has_dict(vm_get(vm), 'id')
        if not kwargs['virtual_machine']:
            log.error('[netboxen]: could not find id for vm: {0}'.format(vm))
            return False

    method = kwargs.pop('method', 'POST')
    if introspect:
        result = {}
        # introspect returns a list of interfaces
        for key, val in introspect_('interfaces').items():
            if val.get('device'):
                app = 'dcim'
            else:
                app = 'virtualization'
            val = _left_join(val, kwargs)
            #  continue
            result[key] = method_(app=app,
                                  method=method,
                                  endpoint='interfaces',
                                  **val)
        # Todo: make salt-stack support `yield`
        # for execution-modules
        return result
    return method_(app=app,
                   method=method,
                   endpoint='interfaces',
                   **kwargs)


def ipaddress_add(address=None, introspect=False, **kwargs):
    """
    Adds ip-address to netbox
    Arguments required, unless introspect is True
    address: str, ip-address with mask
    interface: int, id of parent interface
    enabled: str, 'active'
    id: int, None
    device: device name
    family: int, 4 or 6
    vrf: None,
    tenant: None,
    status: 1,
    role: one of: loopback, secondary, anycast, vip, vrrp, hsrp, glbp, carp
    nat_inside: int, None
    nat_outside: int, None
    dns_name: str, None
    vlan_vid: int, the actual vid not the database id
    prefix: int,
    description: str, None
    method: str, one of POST PUT PATCH, OPTIONS, DELETE, HEAD
    introspect: boolean, add all ips from current minion
    .. code-block:: bash

        salt-call netboxen.ipaddress_add vm=v-machine-l02  name=192.168.0.1 interface=eth0

    """

    kwargs.setdefault('address', address)
    kwargs.setdefault('status', 'active')
    kwargs = _clean_kwargs(kwargs)
    method = kwargs.pop('method', 'POST')
    if introspect:
        result = []
        # introspect returns a list of ips
        for ipaddress in introspect_('ip-addresses'):
            val = _left_join(ipaddress, kwargs)
            result.append(method_(app='ipam',
                                  method=method,
                                  endpoint='ip-addresses',
                                  **val))
        # Todo: convince salt-stack to support `yield`
        return result

    if not kwargs.get('address') and (kwargs.get('vlan') or kwargs.get('prefix')):
        query = _clean_kwargs({'vlan_vid': kwargs.get('vlan'),
                               'is_pool': True,
                               'prefix': kwargs.get('prefix')})
        prefix_id = filter_(app='ipam',
                            endpoint='prefixes',
                            **query).get('id')
        if not isinstance(prefix_id, int):
            raise CommandExecutionError('[netboxen] Could not GET id for {0}'.format(query))
        return method_(app='ipam',
                       method=method,
                       endpoint='prefixes/{0}/available-ips'.format(prefix_id),
                       **kwargs)

    return method_(app='ipam',
                   method=method,
                   endpoint='ip-addresses',
                   **kwargs)


def device_role_get(name=None, **kwargs):
    """
    :name: role name
    see netbox api: GET /dcim/device-roles/ for parameters
    :returns: dict of role or list of roles
    """
    kwargs = _name_int(name, kwargs)
    kwargs = _clean_kwargs(kwargs)
    return filter_(app='dcim',
                   endpoint='device-roles',
                   method=kwargs.pop('method', 'GET'),
                   **kwargs)


def device_role_add(name=None, introspect=False, **kwargs):
    """
    required, unless introspect is False
        :name: str, name of role
        :color: 8 digit hex-string
        :slug: str, slugified name
    vm_role: boolean, can the role have vms
    description:
    :introspect: grab attributes from minion
    method: one of POST PUT PATCH, OPTIONS, DELETE
    CLI Example:
    .. code-block:: bash
        salt '*' netboxen.device_role_add Server slug=server color=black vm_role=True
    """

    kwargs = _name_int(name, kwargs)
    kwargs.setdefault('slug', _slugify(kwargs.get('name')))
    kwargs = _clean_kwargs(kwargs)
    if introspect:
        kwargs = _left_join(introspect_('role'), kwargs)
    return filter_(app='dcim',
                   endpoint='device-roles',
                   method=kwargs.pop('method', 'POST'),
                   **kwargs)


def device_type_get(name=None, **kwargs):
    """
    :name:
    :model:
    :method: POST, PUT, PATCH, OPTIONS, OPTIONS
    returns: list off or single dict
    .. code-block:: bash
        salt '*' netboxen.device_get role=goat platform_get=linux role=server
    """
    if isinstance(name, six.string_types) and isinstance(kwargs.get('model'), type(None)):
        kwargs['model'] = name
    elif isinstance(kwargs.get('model'), int) and kwargs.get('id') is None:
        kwargs['id'] = kwargs['model']
    kwargs = _clean_kwargs(kwargs)
    return filter_(app='dcim',
                   endpoint='device-types',
                   method=kwargs.pop('method', 'GET'),
                   **kwargs)


def device_type_add(name=None, introspect=False, **kwargs):
    """
        :name: model
        :manufacturer:
    :slug: str
    :display_name: bool
    :is_full_depth: bool
    :u_height: int
    :part_number: str
    :subdevice_role: bool
    :tags: list
    :method: one of POST PUT PATCH, OPTIONS, DELETE
    :returns: dict
    """
    if isinstance(name, six.string_types) and not kwargs.get('model'):
        kwargs['model'] = name
    elif isinstance(kwargs.get('model'), int) and kwargs.get('id') is None:
        kwargs['id'] = kwargs.pop('model')
    if isinstance(kwargs.get('model'), six.string_types):
        kwargs.setdefault('slug', _slugify(kwargs['model']))
    kwargs = _clean_kwargs(kwargs)
    if introspect:
        kwargs = _left_join(introspect_('device-types'), kwargs)
    if isinstance(kwargs.get('manufacturer'), six.string_types):
        kwargs['manufacturer'] = _has_dict(manufacturer_get(kwargs['manufacturer']),
                                           'id',
                                           manufacturer_add,
                                           name=kwargs['manufacturer'],
                                           introspect=introspect)
    return method_(app='dcim',
                   method=kwargs.pop('method', 'POST'),
                   endpoint='device-types',
                   **kwargs)


def device_get(name=None, **kwargs):
    """
    :name:
    see netbox api: /dcim/devices/ for parameters
    :returns:
    .. code-block:: bash
        salt '*' netboxen.device_get name=v-mouflon-01 role=goat platform=linux role=server
    """

    kwargs = _name_int(name, kwargs)
    kwargs = _clean_kwargs(kwargs)
    return filter_(app='dcim',
                   method=kwargs.pop('method', 'GET'),
                   endpoint='devices',
                   **kwargs)


def cluster_get(name=None, **kwargs):
    """
    name: cluster name or id
    type: cluster type
    site: site name
    tenant:
    method: one of GET POST PUT PATCH, OPTIONS, DELETE, defaults to GET
    """
    kwargs = _name_int(name, _clean_kwargs(kwargs))
    kwargs.setdefault('slug', _slugify(kwargs.get('name')))
    return filter_(app='virtualization',
                   method=kwargs.pop('method', 'GET'),
                   endpoint='clusters',
                   **kwargs)


def cluster_add(name=None, introspect=False, **kwargs):
    '''
    required args
        :name: str, name of cluster
        :type: string, type of cluster, will be created if not present
    :site: int,
    :group: int, cluster group
    :tenant: int,
    :introspect: grab clustertype from minions __grains__['virtual']
    :method: POST, PUT, PATCH, OPTIONS,
    '''
    if isinstance(name, six.string_types):
        kwargs = _name_int(name, _clean_kwargs(kwargs))
        kwargs.setdefault('slug', _slugify(kwargs.get('name')))
    if introspect:
        kwargs = _left_join(introspect_('cluster'), kwargs)
    if isinstance(kwargs.get('type'), six.string_types):
        kwargs['type'] = _has_dict(cluster_type_get(kwargs['type']),
                                   'id',
                                   cluster_type_add,
                                   name=kwargs['type'],
                                   introspect=introspect)
    # TODO:
    #  if isinstance(kwargs.get('group'), six.string_types):
    return method_(app='virtualization',
                   method=kwargs.pop('method', 'POST'),
                   endpoint='clusters',
                   **kwargs)


def cluster_type_get(name=None, **kwargs):
    """
    name: cluster type
    .. code-block:: bash
        salt '*' netboxen.cluster_type_get xen
    """
    kwargs = _name_int(name, kwargs=kwargs)
    return filter_(app='virtualization',
                   endpoint='cluster-types',
                   method=kwargs.pop('method', 'GET'),
                   **kwargs)


def cluster_type_add(name=None, introspect=False, **kwargs):
    """
    Adds a virtualization cluster type to netbox
    Required fields unless introspect is True
        name: cluster type
    slug: slugified `name`
    description: description
    introspect: sets `name` to the value of grains['virtual']
    .. code-block:: bash
        salt '*' netboxen.cluster_type_add xen description='dom0 hypervisor'
    """
    if introspect:
        kwargs['name'] = __salt__['grains.get']('virtual')
    else:
        kwargs['name'] = name
    kwargs['slug'] = _slugify(kwargs['name'])
    kwargs = _clean_kwargs(kwargs)
    return method_(app='virtualization',
                   endpoint='cluster-types',
                   method=kwargs.pop('method', 'POST'),
                   **kwargs)


def vm_get(name=None, **kwargs):
    """
    name: name of virtualmachine
    method: one of GET POST PUT PATCH, OPTIONS, DELETE defaults to GET
    """
    kwargs = _name_int(name, kwargs=kwargs)
    kwargs = _clean_kwargs(kwargs)
    return filter_(app='virtualization',
                   endpoint='virtual-machines',
                   method=kwargs.pop('method', 'GET'),
                   **kwargs)


def vm_add(name=None, cluster=None, introspect=False, **kwargs):
    """
    Required fields if introspect is False:
        name: name of virtualmachine
        cluster: virtualization clusters name
    role: string
    site: site name
    status: defaults to `1`
    tenant:
    platform: string
    vcpus: nr of cpus
    memory: in MB
    disk: total size in MB
    comments: string
    local_context_data:
    tags:
    .. code-block:: bash
        salt '*' netboxen.vm_add name=v-mouflon-l01 cluster=herd role=goat\
            platform=gnu
    """
    kwargs.setdefault('name', name)
    if isinstance(name, six.string_types):
        kwargs.setdefault('slug', _slugify(name))
    kwargs.setdefault('status', 1)
    kwargs.setdefault('cluster', cluster)
    kwargs = _clean_kwargs(kwargs)
    if introspect:
        kwargs = _left_join(introspect_('virtual-machine'),
                            kwargs)
    if isinstance(kwargs.get('cluster'), six.string_types):
        kwargs['cluster'] = _has_dict(cluster_get(kwargs['cluster']),
                                      'id',
                                      cluster_add,
                                      name=kwargs['cluster'],
                                      introspect=introspect)
    elif not kwargs.get('cluster'):
        CommandExecutionError('specify either cluster or introspect=True')
    if isinstance(kwargs.get('role'), six.string_types):
        kwargs['role'] = _has_dict(device_role_get(kwargs['role']),
                                   'id',
                                   device_role_add,
                                   name=kwargs['role'],
                                   introspect=introspect)
    if isinstance(kwargs.get('platform'), six.string_types):
        kwargs['platform'] = _has_dict(platform_get(kwargs['platform']),
                                       'id',
                                       platform_add,
                                       name=kwargs['platform'],
                                       introspect=introspect)
    return method_(app='virtualization',
                   endpoint='virtual-machines',
                   method=kwargs.pop('method', 'POST'),
                   **kwargs)


def device_add(name=None, introspect=False, **kwargs):
    """
    Add a device to netbox
    Required args:
        name: name of device
        device_type:
        device_role:
        site: site name
    display_name:
    serial:
    asset_tag:
    status: 1
    tenant:
    rack:
    cluster: cluster name, if device has virtual-machines
    comments: string
    local_context_data:
    tags:
    method: one of POST PUT PATCH, OPTIONS, DELETE
    introspect: use values gathered by introspection
    .. code-block:: bash
        salt '*' netboxen.device_add name=v-mouflon-01 role=goat platform_get=linux role=server
    """
    if isinstance(name, six.string_types):
        kwargs.setdefault('name', name)
        kwargs.setdefault('slug', _slugify(kwargs.get('name')))
    kwargs.setdefault('status', "active")
    kwargs = _clean_kwargs(kwargs)
    if introspect:
        kwargs = _left_join(introspect_('device'), kwargs)
    if isinstance(kwargs.get('cluster'), six.string_types):
        kwargs['cluster'] = _has_dict(cluster_get(kwargs['cluster']),
                                      'id',
                                      cluster_add,
                                      name=kwargs['cluster'],
                                      introspect=introspect)
    if isinstance(kwargs.get('device_role'), six.string_types):
        kwargs['device_role'] = _has_dict(device_role_get(kwargs['device_role']),
                                          'id',
                                          device_role_add,
                                          name=kwargs['role'],
                                          introspect=introspect)
    if isinstance(kwargs.get('device_type'), six.string_types):
        kwargs['device_type'] = _has_dict(device_type_get(kwargs['device_type']),
                                          'id',
                                          device_type_add,
                                          model=kwargs['device_type'],
                                          introspect=introspect)
    return method_(app='dcim',
                   method=kwargs.pop('method', 'POST'),
                   endpoint='devices',
                   **kwargs)


def _disksize():
    """
    :returns: int, disk size in mb
    """
    if 'partition.get_block_device' not in __salt__:
        return None
    block_devices = __salt__['partition.get_block_device']()
    size_list = [__salt__['partition.list']('/dev/{0}'.format(
        dev)).get('info', {}).get('size', {})
        for dev in block_devices]
    grand_size = 0
    for _string in size_list:
        _string = ''.join([_int for _int in _string
                           if _int.isdigit() or _int == '.'])
        grand_size += int(float(_string))

    return grand_size


def _randcolor(rand=True):
    """
    :returns: 6 hex, string describing a color
    """
    # Todo: make _randcolor() idemipotent by hashing appropriate
    # system attributes
    if rand:
        return ''.join(random.choice('0123456789abcdef') for n in range(6))


def rir_add(name=None, **kwargs):
    """
    Add an rir
    name: string
    id: integer
    description: string
    is_private: boolean
    slug: string
    """
    if name:
        kwargs.setdefault('name', name)
        kwargs.setdefault('slug', _slugify(name))
    kwargs = _clean_kwargs(kwargs)
    if kwargs.get('introspect'):
        ip_apis = ('https://api.ipify.org',
                   'https://ident.me')
        for _ip in ip_apis:
            pub_ip = salt.utils.http.query(url=_ip,
                                           method='GET').get('body')
            if __utils__['network.is_ip'](pub_ip):
                break
    return __salt__['network.traceroute'](pub_ip)


__func_alias__ = {
    'filter_': 'filter',
    'introspect_': 'introspect',
    'method_': 'method'
}

