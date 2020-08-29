
import salt.utils
import logging
log = logging.getLogger(__name__)

try:
    if salt.utils.path.which('lldpctl'):
        # TODO: check for JSON support in lldpctl -vv output
        HAS_LLDP = True
    else:
        HAS_LLDP = False
except ImportError as e:
    HAS_LLDP = False


def __virtual__():
    '''
    lldpd must be in path.
    '''
    if HAS_LLDP:
        return HAS_LLDP
    else:
        log.trace('lldp: failed to find lldpctl binary')
    return False


def ctl_(name):
    """
    invokes lldpctl command
    :returns: lldpctl output as a dict
    .. code-block:: bash
        salt '*' lldp.neighbors eth0
    """

    ret = __salt__['cmd.run']('lldpcli -f json {0}'.format(name))
    try:
        return __utils__['json.loads'](ret)
    except Exception as e:
        log.error('lldp: {0}'.format(str(e)))
        return False


def _ifaces():
    return [iface for iface, val in
            __salt__['network.interfaces']().items()
            if iface not in ('lo', 'lo0')]


def neighbors():
    """
    show neighbors on all ports
    :returns: lldpctl output as a dict
    .. code-block:: bash
        salt '*' lldp.neighbors
    """
    return ctl_('show neighbors').get('lldp').get('interface')


def interfaces():
    """
    show configuration for local interfaces
    :returns: lldpctl output as a dict
    .. code-block:: bash
        salt '*' lldp.interfaces
    """
    return ctl_('show interfaces').get('lldp').get('interface')


def chassis():
    """
    show configuration for local chassis
    :returns: dict
    .. code-block:: bash
        salt '*' lldp.interfaces
    """
    chassis = ctl_('show chassis').get('local-chassis').get('chassis')
    if len(chassis.values()) == 1:
        return next(iter(chassis.values()))
    return chassis


def statistics():
    """
    show statistics for local interfaces
    :returns: lldpctl output as a dict
    .. code-block:: bash
        salt '*' lldp.interfaces
    """
    ifaces = ctl_('show statistics').get('lldp').get('interface')
    for key in ifaces:
        for item in ifaces[key]:
            item = ifaces[key]
            log.error(str(item))
            #  item=next(iter(item.values()))
    return ifaces


def configuration():
    """
    Show local configuration
    :returns: lldpctl output as a dict
    .. code-block:: bash
        salt '*' lldp.configuration
    """
    conf = ctl_('show configuration').get('configuration').get('config')
    if isinstance(chassis,list) and len(chassis.values()) == 1:
        return next(iter(chassis.values()))
    return conf


def running_configuration():
    """
    Show running configuration
    :returns: lldpctl output as a dict
    .. code-block:: bash
        salt '*' lldp.configuration
    """
    return ctl_('show running-configuration').get('configuration').get('config')


def configure_location(ports=None,
                       name=None,
                       country=None,
                       language=None,
                       country_subdivision=None,
                       county=None,
                       city=None,
                       city_division=None,
                       block=None,
                       street=None,
                       direction=None,
                       trailing_street=None,
                       street_suffix=None,
                       number=None,
                       number_suffix=None,
                       landmark=None,
                       additional=None,
                       zip=None,
                       building=None,
                       unit=None,
                       floor=None,
                       room=None,
                       place_type=None,
                       script=None):
    """
    configure running med location address configuration
    ports: interface to configure
    country: Specify country (mandatory)
    language: Language
    country_subdivision: Country subdivision
    county: County
    city: City
    city_division: City division
    block: Block
    street: Street
    direction: Direction
    trailing_street-suffix: Trailing street suffix
    street_suffix: Street suffix
    number: Number
    number_suffix: Number suffix
    landmark: Landmark
    additional: Additional
    name: Name
    zip: ZIP
    building: Building
    unit: Unit
    floor: Floor
    room: Room
    place_type: Place type
    script: Script
    :returns: lldpctl output as a dict
    .. code-block:: bash
        salt '*' lldp.configuration
    """

    # configure ports eth1 med location address US street "Commercial Road" city "Roseville"
    args = locals().items()
    if ports:
        ports = 'ports {0}'.format(args.pop('ports'))
    else:
        ports = ''
    config = ['{0} "{1}"'.format(key.replace('_', '-'), str(val))
              for key, val in args if val is not None]
    config = 'configure {0} med location address {1}'.format(ports, ' '.join(config))
    log.error(config)
    return ctl_(config)

    #  description  Override chassis description
    #  chassisid  Override chassis ID
    #  platform  Override platform description
    #  hostname  Override system name
    #  max-neighbors  Set maximum number of neighbors per port
    #  interface  Interface related items
    #  description  Override chassis description
    #  chassisid  Override chassis ID
    #  platform  Override platform description
    #  hostname  Override system name
    #  max-neighbors  Set maximum number of neighbors per port
    #  ip  IP related options
#  bond-slave-src-mac-type  Set LLDP bond slave source MAC type

#  Get-NetNeighbor | ConvertTo-Json
#  If (!(Get-WindowsOptionalFeature -Online -FeatureName 'DataCenterBridging').State -eq 'Enabled') {
    #  Enable-WindowsOptionalFeature -Online -FeatureName 'DataCenterBridging'
#  }


__outputter__ = {
    'run': 'txt'
}

__func_alias__ = {
    'ctl_': 'ctl',
}
