#!/usr/bin/env python3

####################################################################################
#
# Copyright (c) 2018, Simon Taylor
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# Author: Simon Taylor
#
# This script is intended as a one-stop-shop for Palo Alto API requests.
#
# Current abilities:
#   - print all objects and Security/NAT rules from a Palo Alto firewall or Panorama Device Group to screen
#   - write all objects and Security/NAT rules from a Palo Alto firewall or Panorama Device Group to Standard CSV format
#   - create/edit/delete AddressObjects from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete AddressGroups from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete ApplicationObjects from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete ApplicationGroups from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete ServiceObjects from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete ServiceGroups from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete Tags from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete Dynamic IPs from a Palo Alto firewall
#   - create/edit/delete StaticRoutes from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete SecurityRules from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete NatRules from a Palo Alto firewall or Panorama Device Group
#   - emails log output file to recipients
#
# Future abilities:
#   - create/edit/delete Vsys from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete VirtualRouters from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete Interfaces from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete SecurityProfileGroups from a Palo Alto firewall or Panorama Device Group
#   - create/edit/delete ApplicationFilters from a Palo Alto firewall or Panorama Device Group
#
# Cannot support:
#   - Pandevice does not return "dependent apps" for an ApplicationObject so cannot check for dependent apps in this script
#
# Notes:
#   - It is intended that the CSV format be created by other tools
#   - This script might not be too 'Pythonic' as I'm more used to Perl ;)
#
# Pandevice Documentation:
#   - https://pandevice.readthedocs.io/en/latest/
#   - https://pandevice.readthedocs.io/en/latest/reference.html
#   - https://github.com/PaloAltoNetworks/pandevice
#   - https://github.com/PaloAltoNetworks/pandevice-tutorial
#   - https://gitter.im/PaloAltoNetworks/pandevice
#
# Pandevice Methods:
#   - the create() method will never remove a variable or object, only add or change it. This method is nondestructive. If the object exists, the variables are added to the device without changing existing variables on the device. 
#     If a variables already exists on the device and this object has a different value, the value on the firewall is changed to the value in this object.
#   - the apply() method is destructive overwriting the configuration item on the device - Apply this object to the device, replacing any existing object of the same name
#   - the delete() method removes the object from the live device and the configuration tree - Deletes this object from the firewall
#   - the update() method changes the value of a variable - updates live device
#
####################################################################################

__author__ = 'simon-taylor'
__copyright__ = 'Simon Taylor 2018'
__credits__ = ['simon-taylor']
__maintainer__ = ['simon-taylor']
__email__ = 'sjtaylor@gmx.com'
__status__ = "Production"
__version__ = '1.4'
__date__ = '27/11/18'
__revision__ = '29/03/19'

####################################################################################
#
# change these for mail server/email settings
#
####################################################################################

__email_domain__ = '@example.com'
__api_notification_email__ = 'alerts' + __email_domain__
__mail_server__ = '169.254.1.1'
__from_address__ = 'apiserver'  + __email_domain__

####################################################################################

import argparse
import logging
import os
import sys
import pandevice
import pprint
import csv
import ipaddress
import time
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
today = datetime.today()

from collections import OrderedDict
from collections import defaultdict
from more_itertools import unique_everseen
from pandevice.base import PanDevice
from pandevice.device import Vsys
from pandevice.device import SystemSettings
from pandevice.firewall import Firewall
from pandevice.network import VirtualRouter
from pandevice.network import StaticRoute
from pandevice.network import Zone
from pandevice.network import AggregateInterface
from pandevice.network import EthernetInterface
from pandevice.network import Layer3Subinterface
from pandevice.network import TunnelInterface
from pandevice.network import LoopbackInterface
from pandevice.network import VlanInterface
from pandevice.objects import AddressObject
from pandevice.objects import AddressGroup
from pandevice.objects import ApplicationContainer
from pandevice.objects import ApplicationFilter
from pandevice.objects import ApplicationGroup
from pandevice.objects import ApplicationObject
from pandevice.objects import ServiceGroup
from pandevice.objects import ServiceObject
from pandevice.objects import SecurityProfileGroup
from pandevice.objects import Tag
from pandevice.panorama import Panorama
from pandevice.panorama import DeviceGroup
from pandevice.panorama import Template
from pandevice.panorama import TemplateStack
from pandevice.policies import SecurityRule
from pandevice.policies import NatRule
from pandevice.policies import PreRulebase
from pandevice.policies import PostRulebase
from pandevice.policies import Rulebase

# this next line needed to 'refreshall' Templates
from pandevice import ha

####################################################################################
#
# Custom Classes
#
####################################################################################

class Dip:
    def __init__(self, ip, tag):
        # ip (list or str)
        # tags (list or str)
        self.ip = ip
        self.tag = tag
        self.name = '-'.join((str(ip), str(tag)))

class DeleteObject:
    def __init__(self, name, type):
        self.name = name
        self.type = type

class EditObject:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

class ModifyGroup:
    def __init__(self, name, type, members, action, description):
        self.name = name
        self.type = type
        self.action = action
        self.members = members
        self.description = description

class RenameObject:
    def __init__(self, name, type, newname):
        self.name = name
        self.type = type
        self.newname = newname

####################################################################################
#
# Update Functions
#
####################################################################################

def update_objects(objects, tree, devtype, devname, action, args, logger, filename, failures, available_tag_names, available_address_names, available_address_group_names, available_service_names, available_service_group_names, available_application_names, available_application_group_names, existing_rule_names, existing_zone_names, existing_nat_names, existing_interface_names, existing_route_names, existing_dip_names):

    if objects:

        if args.verbose:
            logger.info('{} \'{}\': Updating objects, (action \'{}\')'.format(devtype, devname, action))

        null_set = set()

        for o in objects:
            if issubclass(type(o), DeleteObject):
                if o.type == 'address':
                    # remove from all AddressGroup first!
                    for group in available_address_group_names:
                        p = ModifyGroup(name=group, type='address-group', members=[o.name], action=None, description=None)
                        remove_from_palo_group(args, logger, p, available_address_group_names, available_address_names, devtype, AddressGroup, tree, filename, failures)
                    delete_palo_object(args, logger, o, available_address_names, devtype, AddressObject, tree, filename, failures)
                elif o.type == 'address-group':
                    delete_palo_object(args, logger, o, available_address_group_names, devtype, AddressGroup, tree, filename, failures)
                elif o.type == 'service':
                    # remove from all ServiceGroup first!
                    for group in available_service_group_names:
                        p = ModifyGroup(name=group, type='service-group', members=[o.name], action=None, description=None)
                        remove_from_palo_group(args, logger, p, available_service_group_names, available_service_names, devtype, ServiceGroup, tree, filename, failures)
                    delete_palo_object(args, logger, o, available_service_names, devtype, ServiceObject, tree, filename, failures)
                elif o.type == 'service-group':
                    delete_palo_object(args, logger, o, available_service_group_names, devtype, ServiceGroup, tree, filename, failures)
                elif o.type == 'tag':
                    delete_palo_object(args, logger, o, available_tag_names, devtype, Tag, tree, filename, failures)
                elif o.type == 'application':
                    # remove from all ApplicationGroup first!
                    for group in available_application_group_names:
                        p = ModifyGroup(name=group, type='application-group', members=[o.name], action=None, description=None)
                        remove_from_palo_group(args, logger, p, available_application_group_names, available_application_names, devtype, ApplicationGroup, tree, filename, failures)
                    delete_palo_object(args, logger, o, available_application_names, devtype, ApplicationObject, tree, filename, failures)
                elif o.type == 'application-group':
                    delete_palo_object(args, logger, o, available_application_group_names, devtype, ApplicationGroup, tree, filename, failures)
                elif o.type == 'application-filter':
                    delete_palo_object(args, logger, o, null_set, devtype, ApplicationFilter, tree, filename, failures)
                elif o.type == 'security-rule':
                    delete_palo_object(args, logger, o, existing_rule_names, devtype, SecurityRule, tree, filename, failures)
                elif o.type == 'nat-rule':
                    delete_palo_object(args, logger, o, existing_nat_names, devtype, NatRule, tree, filename, failures)
                elif o.type == 'pre-security-rule':
                    for grandchild in tree.children:
                        if issubclass(type(grandchild), PreRulebase):
                            delete_palo_object(args, logger, o, existing_rule_names, devtype, SecurityRule, grandchild, filename, failures)
                elif o.type == 'pre-nat-rule':
                    for grandchild in tree.children:
                        if issubclass(type(grandchild), PreRulebase):
                            delete_palo_object(args, logger, o, existing_nat_names, devtype, NatRule, grandchild, filename, failures)
                elif o.type == 'post-security-rule':
                    for grandchild in tree.children:
                        if issubclass(type(grandchild), PostRulebase):
                            delete_palo_object(args, logger, o, existing_rule_names, devtype, SecurityRule, grandchild, filename, failures)
                elif o.type == 'post-nat-rule':
                    for grandchild in tree.children:
                        if issubclass(type(grandchild), PostRulebase):
                            delete_palo_object(args, logger, o, existing_nat_names, devtype, NatRule, grandchild, filename, failures)
                elif o.type == 'route':
                    delete_palo_object(args, logger, o, null_set, devtype, StaticRoute, tree, filename, failures)
                else:
                    logger.warn('update_objects - DeleteObject - Unsupported type \'{}\' for \'{}\', (contact your nearest Security Engineering resource). skipping...'.format(o.type, o.name))
            elif issubclass(type(o), EditObject):
                if o.type == 'address':
                    edit_palo_object(args, logger, o, available_address_names, devtype, AddressObject, tree, filename, failures)
                elif o.type == 'address-group':
                    edit_palo_object(args, logger, o, available_address_group_names, devtype, AddressGroup, tree, filename, failures)
                elif o.type == 'service':
                    edit_palo_object(args, logger, o, available_service_names, devtype, ServiceObject, tree, filename, failures)
                elif o.type == 'service-group':
                    edit_palo_object(args, logger, o, available_service_group_names, devtype, ServiceGroup, tree, filename, failures)
                elif o.type == 'tag':
                    edit_palo_object(args, logger, o, available_tag_names, devtype, Tag, tree, filename, failures)
                elif o.type == 'application':
                    edit_palo_object(args, logger, o, available_application_names, devtype, ApplicationObject, tree, filename, failures)
                elif o.type == 'application-group':
                    edit_palo_object(args, logger, o, available_application_group_names, devtype, ApplicationGroup, tree, filename, failures)
                elif o.type == 'application-filter':
                    edit_palo_object(args, logger, o, null_set, devtype, ApplicationFilter, tree, filename, failures)
                elif o.type == 'security-rule':
                    edit_palo_object(args, logger, o, existing_rule_names, devtype, SecurityRule, tree, filename, failures)
                elif o.type == 'nat-rule':
                    edit_palo_object(args, logger, o, existing_nat_names, devtype, NatRule, tree, filename, failures)
                elif o.type == 'pre-security-rule':
                    for grandchild in tree.children:
                        if issubclass(type(grandchild), PreRulebase):
                            edit_palo_object(args, logger, o, existing_rule_names, devtype, SecurityRule, grandchild, filename, failures)
                elif o.type == 'pre-nat-rule':
                    for grandchild in tree.children:
                        if issubclass(type(grandchild), PreRulebase):
                            edit_palo_object(args, logger, o, existing_nat_names, devtype, NatRule, grandchild, filename, failures)
                elif o.type == 'post-security-rule':
                    for grandchild in tree.children:
                        if issubclass(type(grandchild), PostRulebase):
                            edit_palo_object(args, logger, o, existing_rule_names, devtype, SecurityRule, grandchild, filename, failures)
                elif o.type == 'post-nat-rule':
                    for grandchild in tree.children:
                        if issubclass(type(grandchild), PostRulebase):
                            edit_palo_object(args, logger, o, existing_nat_names, devtype, NatRule, grandchild, filename, failures)
                elif o.type == 'route':
                    edit_palo_object(args, logger, o, null_set, devtype, StaticRoute, tree, filename, failures)
                else:
                    logger.warn('update_objects - EditObject - Unsupported type \'{}\' for \'{}\', (contact your nearest Security Engineering resource). skipping...'.format(o.type, o.name))
            elif issubclass(type(o), ModifyGroup):
                if o.type == 'address-group':
                    if o.action == 'addtogroup':
                        add_to_palo_group(args, logger, o, available_address_group_names, available_address_names, devtype, AddressGroup, tree, filename, failures)
                    elif o.action == 'removefromgroup':
                        remove_from_palo_group(args, logger, o, available_address_group_names, available_address_names, devtype, AddressGroup, tree, filename, failures)
                    else:
                        logger.warn('update_objects - ModifyGroup - Unsupported action \'{}\' for \'{}\', (contact your nearest Security Engineering resource). skipping...'.format(o.action, o.name))
                elif o.type == 'service-group':
                    if o.action == 'addtogroup':
                        add_to_palo_group(args, logger, o, available_service_group_names, available_service_names, devtype, ServiceGroup, tree, filename, failures)
                    elif o.action == 'removefromgroup':
                        remove_from_palo_group(args, logger, o, available_service_group_names, available_service_names, devtype, ServiceGroup, tree, filename, failures)
                    else:
                        logger.warn('update_objects - ModifyGroup - Unsupported action \'{}\' for \'{}\', (contact your nearest Security Engineering resource). skipping...'.format(o.action, o.name))
                elif o.type == 'application-group':
                    if o.action == 'addtogroup':
                        add_to_palo_group(args, logger, o, available_application_group_names, available_application_names, devtype, ApplicationGroup, tree, filename, failures)
                    elif o.action == 'removefromgroup':
                        remove_from_palo_group(args, logger, o, available_application_group_names, available_application_names, devtype, ApplicationGroup, tree, filename, failures)
                    else:
                        logger.warn('update_objects - ModifyGroup - Unsupported action \'{}\' for \'{}\', (contact your nearest Security Engineering resource). skipping...'.format(o.action, o.name))
                else:
                    logger.warn('update_objects - ModifyGroup - Unsupported type \'{}\' for \'{}\', (contact your nearest Security Engineering resource). skipping...'.format(o.type, o.name))
            else:
                if action == 'create':
                    if issubclass(type(o), AddressGroup):
                        create_palo_address_group(args, logger, o, available_address_group_names, available_tag_names, available_address_names, devtype, tree, filename, failures)
                    elif issubclass(type(o), AddressObject):
                        create_palo_address(args, logger, o, available_address_names, available_tag_names, devtype, tree, filename, failures)
                    elif issubclass(type(o), ApplicationFilter):
                        logger.warn('Yet to support creation of ApplicationFilter objects')
                    elif issubclass(type(o), ApplicationGroup):
                        create_palo_application_group(args, logger, o, available_application_group_names, available_application_names, devtype, tree, filename, failures)
                    elif issubclass(type(o), ApplicationObject):
                        create_palo_application(args, logger, o, available_application_names, devtype, tree, filename, failures)
                    elif issubclass(type(o), ServiceGroup):
                        create_palo_service_group(args, logger, o, available_service_group_names, available_tag_names, available_service_names, devtype, tree, filename, failures)
                    elif issubclass(type(o), ServiceObject):
                        create_palo_service(args, logger, o, available_service_names, available_tag_names, devtype, tree, filename, failures)
                    elif issubclass(type(o), Tag):
                        create_palo_tag(args, logger, o, available_tag_names, devtype, tree, filename, failures)
                    elif issubclass(type(o), Dip):
                        create_palo_dip(args, logger, o, existing_dip_names, devtype, tree, filename, failures)
                    elif issubclass(type(o), StaticRoute):
                        create_palo_route(args, logger, o, existing_route_names, devtype, tree, filename, failures)
                    elif issubclass(type(o), SecurityRule):
                        create_palo_rule(args, logger, o, existing_rule_names, existing_zone_names, available_address_names, available_address_group_names, available_service_names, available_service_group_names, available_application_names, available_application_group_names, available_tag_names, devtype, tree, filename, failures)
                    elif issubclass(type(o), NatRule):
                        create_palo_nat(args, logger, o, existing_nat_names, existing_zone_names, available_address_names, available_address_group_names, available_service_names, available_service_group_names, existing_interface_names, available_tag_names, devtype, tree, filename, failures)
                elif action == 'delete':
                    if issubclass(type(o), Dip):
                        delete_palo_dip(args, logger, o, existing_dip_names, devtype, tree, filename, failures)
                else:
                    logger.warn('update_objects: Unsupported action \'{}\' for type \'{}\' name \'{}\', (contact your nearest Security Engineering resource). skipping...'.format(action, str(type(o)), o.name))

####################################################################################
#
# Create Functions
#
####################################################################################

def create_palo_nat(args, logger, new_nat_rule, rules, zones, addresses, address_groups, services, service_groups, interfaces, tags, devtype, rulebase, device, failures):

    # takes a Rulebase object 'new_nat_rule' and checks dependencies etc...
    # note its important here to compare same types. set contains <class 'str'> so use a.name as that is also <class 'str'>

    # add in 'any' where appropriate as this is a valid option
    zones.add('any')
    addresses.add('any')
    services.add('any')
    interfaces.add('any')

    if not args.no_checks:
        # check not already existing
        if new_nat_rule.name not in rules:
            for zone in new_nat_rule.fromzone:
                if zone not in zones:
                    logger.warn("{} \'{}\': Not attempting to create NatRule \'{}\'. Invalid fromzone \'{}\'! Skipping...".format(devtype, device, new_nat_rule, zone))
                    break
            else:
                for source in new_nat_rule.source:
                    if source not in addresses and source not in address_groups:
                        logger.warn("{} \'{}\': Not attempting to create NatRule \'{}\'. Invalid source \'{}\'! Skipping...".format(devtype, device, new_nat_rule, source))
                        break
                else:
                    for zone in new_nat_rule.tozone:
                        if zone not in zones:
                            logger.warn("{} \'{}\': Not attempting to create NatRule \'{}\'. Invalid tozone \'{}\'! Skipping...".format(devtype, device, new_nat_rule, zone))
                            break
                    else:
                        if new_nat_rule.service in services or new_nat_rule.service in service_groups:
                            if new_nat_rule.to_interface is None or new_nat_rule.to_interface in interfaces:
                                if new_nat_rule.tag is not None:
                                    for tag in new_nat_rule.tag:
                                        if tag not in tags:
                                            logger.warn("{} \'{}\': Not attempting to create NatRule \'{}\'. Invalid tag \'{}\'! Skipping...".format(devtype, device, new_nat_rule, tag))
                                            break
                                    else:
                                        create_palo_object(args, logger, new_nat_rule, 'NatRule', rulebase, device, devtype, failures)
                                else:
                                    create_palo_object(args, logger, new_nat_rule, 'NatRule', rulebase, device, devtype, failures)
                            else:
                                logger.warn("{} \'{}\': Not attempting to create NatRule \'{}\'. Invalid interface \'{}\'! Skipping...".format(devtype, device, new_nat_rule, new_nat_rule.to_interface))
                        else:
                            logger.warn("{} \'{}\': Not attempting to create NatRule \'{}\'. Invalid service \'{}\'! Skipping...".format(devtype, device, new_nat_rule, new_nat_rule.service))
        else:
            logger.warn("{} \'{}\': Not attempting to create NatRule \'{}\'. Already exists! Skipping...".format(devtype, device, new_nat_rule))
    else:
        if not args.quiet:
            logger.info("{} \'{}\': \'--no-checks\' requested while attempting to create NatRule \'{}\'. Watch for errors...".format(devtype, device, new_nat_rule))
        create_palo_object(args, logger, new_nat_rule, 'NatRule', rulebase, device, devtype, failures)

def create_palo_rule(args, logger, new_sec_rule, rules, zones, addresses, address_groups, services, service_groups, applications, application_groups, tags, devtype, rulebase, device, failures):

    # takes a SecurityRule object 'new_sec_rule' and checks dependencies etc...
    # note its important here to compare same types. set contains <class 'str'> so use a.name as that is also <class 'str'>

    # add in 'any' (or other fixed values) where appropriate as this is a valid option
    zones.add('any')
    addresses.add('any')
    applications.add('any')
    services.add('any')
    services.add('application-default')

    if not args.no_checks:
        # check not already existing
        if new_sec_rule.name not in rules:
            for zone in new_sec_rule.fromzone:
                if zone not in zones:
                    logger.warn("{} \'{}\': Not attempting to create SecurityRule \'{}\'. Invalid fromzone \'{}\'! Skipping...".format(devtype, device, new_sec_rule, zone))
                    break
            else:
                for source in new_sec_rule.source:
                    if source not in addresses and source not in address_groups:
                        logger.warn("{} \'{}\': Not attempting to create SecurityRule \'{}\'. Invalid source \'{}\'! Skipping...".format(devtype, device, new_sec_rule, source))
                        break
                else:
                    for zone in new_sec_rule.tozone:
                        if zone not in zones:
                            logger.warn("{} \'{}\': Not attempting to create SecurityRule \'{}\'. Invalid tozone \'{}\'! Skipping...".format(devtype, device, new_sec_rule, zone))
                            break
                    else:
                        for destination in new_sec_rule.destination:
                            if destination not in addresses and destination not in address_groups:
                                logger.warn("{} \'{}\': Not attempting to create SecurityRule \'{}\'. Invalid destination \'{}\'! Skipping...".format(devtype, device, new_sec_rule, destination))
                                break
                        else:
                            for application in new_sec_rule.application:
                                if application not in applications and application not in application_groups:
                                    logger.warn("{} \'{}\': Not attempting to create SecurityRule \'{}\'. Invalid application \'{}\'! Skipping...".format(devtype, device, new_sec_rule, application))
                                    break
                            else:
                                for service in new_sec_rule.service:
                                    if service not in services and service not in service_groups:
                                        logger.warn("{} \'{}\': Not attempting to create SecurityRule \'{}\'. Invalid service \'{}\'! Skipping...".format(devtype, device, new_sec_rule, service))
                                        break
                                else:
                                    if new_sec_rule.tag is not None:
                                        for tag in new_sec_rule.tag:
                                            if tag not in tags:
                                                logger.warn("{} \'{}\': Not attempting to create SecurityRule \'{}\'. Invalid tag \'{}\'! Skipping...".format(devtype, device, new_sec_rule, tag))
                                                break
                                        else:
                                            create_palo_object(args, logger, new_sec_rule, 'SecurityRule', rulebase, device, devtype, failures)
                                    else:
                                        create_palo_object(args, logger, new_sec_rule, 'SecurityRule', rulebase, device, devtype, failures)
        else:
            logger.warn("{} \'{}\': Not attempting to create SecurityRule \'{}\'. Already exists! Skipping...".format(devtype, device, new_sec_rule))
    else:
        create_palo_object(args, logger, new_sec_rule, 'SecurityRule', rulebase, device, devtype, failures)

def create_palo_application(args, logger, new_application, applications, devtype, tree, device, failures):

    # takes an Application object 'new_application' and checks dependencies etc...

    if not args.no_checks:
        if new_application.name not in applications:
            create_palo_object(args, logger, new_application, 'Application', tree, device, devtype, failures)
        else:
            logger.warn("{} \'{}\': Not attempting to create Application \'{}\'. Already exists! Skipping...".format(devtype, device, new_application))
    else:
        create_palo_object(args, logger, new_application, 'Application', tree, device, devtype, failures)

def create_palo_application_group(args, logger, new_application_group, application_groups, applications, devtype, tree, device, failures):

    # takes an ApplicationGroup object 'new_application_group' and checks dependencies etc...
    # note its important here to compare same types. set contains <class 'str'> so use a.name as that is also <class 'str'>
    # check not already existing

    if not args.no_checks:
        if new_application_group.name not in application_groups:
            if new_application_group.value:
                # check members
                for appid in new_application_group.value:
                    if appid not in applications:
                        logger.warn("{} \'{}\': Not attempting to create ApplicationGroup \'{}\'. Missing member \'{}\'! Skipping...".format(devtype, device, new_application_group, appid))
                        break
                else:
                    # here we can check for dependent apps
                    create_palo_object(args, logger, new_application_group, 'ApplicationGroup', tree, device, devtype, failures)
            else:
                logger.warn("{} \'{}\': Not attempting to create ApplicationGroup \'{}\'. No members! Skipping...".format(devtype, device, new_application_group))
        else:
            logger.warn("{} \'{}\': Not attempting to create ApplicationGroup \'{}\'. Already exists! Skipping...".format(devtype, device, new_application_group))
    else:
        create_palo_object(args, logger, new_application_group, 'ApplicationGroup', tree, device, devtype, failures)

def create_palo_address_group(args, logger, new_address_group, address_groups, tags, addresses, devtype, tree, device, failures):

    # takes an AddressGroup object 'new_address_group' and checks dependencies etc...
    # note its important here to compare same types. set contains <class 'str'> so use a.name as that is also a <class 'str'>

    if not args.no_checks:
        # check not already existing
        if new_address_group.name not in address_groups:
            # check for tag first as that's a common field (don't confuse filter tag with group tag!)
            if new_address_group.tag:
                for tag in new_address_group.tag:
                    if tag not in tags:
                        logger.warn("{} \'{}\': Not attempting to create AddressGroup \'{}\'. Missing tag \'{}\'! Skipping...".format(devtype, device, new_address_group, tag))
                        break
                else:
                    # all tags were found, check for group type
                    if new_address_group.static_value:
                        # we are a static group, check members
                        for member in new_address_group.static_value:
                            if member not in addresses and member not in address_groups:
                                logger.warn("{} \'{}\': Not attempting to create AddressGroup \'{}\'. Missing member \'{}\'! Skipping...".format(devtype, device, new_address_group, member))
                                break
                        else:
                            create_palo_object(args, logger, new_address_group, 'AddressGroup', tree, device, devtype, failures)
                    elif new_address_group.dynamic_value:
                        # we are a dynamic group - check each tag filter exists tricky bec dynamic_value = (str) 
                        tmp = new_address_group.dynamic_value.replace("'", "")
                        pattern = tmp.replace(" ", "")
                        li = list(pattern.split("and"))
                        for item in li:
                            if item not in tags:
                                logger.warn("{} \'{}\': Not attempting to create AddressGroup \'{}\'. Missing filter \'{}\'! Skipping...".format(devtype, device, new_address_group, pattern))
                                break
                        else:
                            create_palo_object(args, logger, new_address_group, 'AddressGroup', tree, device, devtype, failures)
            else:
                # no tags requested, check for group type
                if new_address_group.static_value:
                    # we are a static group, check members
                    for member in new_address_group.static_value:
                        if member not in addresses and member not in address_groups:
                            logger.warn("{} \'{}\': Not attempting to create AddressGroup \'{}\'. Missing member \'{}\'! Skipping...".format(devtype, device, new_address_group, member))
                            break
                    else:
                        create_palo_object(args, logger, new_address_group, 'AddressGroup', tree, device, devtype, failures)
                elif new_address_group.dynamic_value:
                    # we are a dynamic group - check each tag filter exists tricky bec dynamic_value = (str) 
                    tmp = new_address_group.dynamic_value.replace("'", "")
                    pattern = tmp.replace(" ", "")
                    li = list(pattern.split("and"))
                    for item in li:
                        if item not in tags:
                            logger.warn("{} \'{}\': Not attempting to create AddressGroup \'{}\'. Missing filter \'{}\'! Skipping...".format(devtype, device, new_address_group, pattern))
                            break
                    else:
                        create_palo_object(args, logger, new_address_group, 'AddressGroup', tree, device, devtype, failures)
        else:
            logger.warn("{} \'{}\': Not attempting to create AddressGroup \'{}\'. Already exists! Skipping...".format(devtype, device, new_address_group))
    else:
        create_palo_object(args, logger, new_address_group, 'AddressGroup', tree, device, devtype, failures)

def create_palo_address(args, logger, new_address, addresses, tags, devtype, tree, device, failures):

    # takes an AddressObject object 'new_address' and checks dependencies etc...
    # note its important here to compare same types. set contains <class 'str'> so use a.name as that is also a <class 'str'>

    if not args.no_checks:
        # check not already existing
        if new_address.name not in addresses:
            # if tag requested check that also exists
            if new_address.tag:
                for tag in new_address.tag:
                    if tag not in tags:
                        logger.warn("{} \'{}\': Not attempting to create AddressObject \'{}\'. Missing tag \'{}\'! Skipping...".format(devtype, device, new_address, tag))
                        break
                else:
                    # all tags were found, create AddressObject
                    create_palo_object(args, logger, new_address, 'AddressObject', tree, device, devtype, failures)
            else:
                # create AddressObject
                create_palo_object(args, logger, new_address, 'AddressObject', tree, device, devtype, failures)
        else:
            logger.warn("{} \'{}\': Not attempting to create AddressObject \'{}\'. Already exists! Skipping...".format(devtype, device, new_address))
    else:
        create_palo_object(args, logger, new_address, 'AddressObject', tree, device, devtype, failures)

def create_palo_service(args, logger, new_service, services, tags, devtype, tree, device, failures):

    # takes a ServiceObject object 'new_service' and checks dependencies etc...
    # note its important here to compare same types. set contains <class 'str'> so use a.name as that is also a <class 'str'>

    if not args.no_checks:
        # check not already existing
        if new_service.name not in services:
            # if tag requested check that also exists
            if new_service.tag:
                for tag in new_service.tag:
                    if tag not in tags:
                        logger.warn("{} \'{}\': Not attempting to create ServiceObject \'{}\'. Missing tag \'{}\'! Skipping...".format(devtype, device, new_service, tag))
                        break
                else:
                    # all tags were found, create ServiceObject
                    create_palo_object(args, logger, new_service, 'ServiceObject', tree, device, devtype, failures)
            else:
                # create ServiceObject
                create_palo_object(args, logger, new_service, 'ServiceObject', tree, device, devtype, failures)
        else:
            logger.warn("{} \'{}\': Not attempting to create ServiceObject \'{}\'. Already exists! Skipping...".format(devtype, device, new_service))
    else:
        create_palo_object(args, logger, new_service, 'ServiceObject', tree, device, devtype, failures)

def create_palo_service_group(args, logger, new_service_group, service_groups, tags, services, devtype, tree, device, failures):

    # takes a ServiceGroup object 'new_service_group' and checks dependencies etc...
    # note its important here to compare same types. set contains <class 'str'> so use a.name as that is also a <class 'str'>

    if not args.no_checks:
        # check not already existing
        if new_service_group.name not in service_groups:
            # check for tag first as that's a common field
            if new_service_group.tag:
                for tag in new_service_group.tag:
                    if tag not in tags:
                        logger.warn("{} \'{}\': Not attempting to create ServiceGroup \'{}\'. Missing tag \'{}\'! Skipping...".format(devtype, device, new_service_group, tag))
                        break
                else:
                    # all tags were found, check for group members
                    if new_service_group.value:
                        for member in new_service_group.value:
                            if member not in services:
                                logger.warn("{} \'{}\': Not attempting to create ServiceGroup \'{}\'. Missing member \'{}\'! Skipping...".format(devtype, device, new_service_group, member))
                                break
                        else:
                            create_palo_object(args, logger, new_service_group, 'ServiceGroup', tree, device, devtype, failures)
                    else:
                        logger.warn("{} \'{}\': Not attempting to create ServiceGroup \'{}\'. No members! Skipping...".format(devtype, device, new_service_group))
            else:
                # no tags requested, check for group members
                if new_service_group.value:
                    for member in new_service_group.value:
                        if member not in services:
                            logger.warn("{} \'{}\': Not attempting to create ServiceGroup \'{}\'. Missing member \'{}\'! Skipping...".format(devtype, device, new_service_group, member))
                            break
                    else:
                        create_palo_object(args, logger, new_service_group, 'ServiceGroup', tree, device, devtype, failures)
                else:
                    logger.warn("{} \'{}\': Not attempting to create ServiceGroup \'{}\'. No members! Skipping...".format(devtype, device, new_service_group))
        else:
            logger.warn("{} \'{}\': Not attempting to create ServiceGroup \'{}\'. Already exists! Skipping...".format(devtype, device, new_service_group))
    else:
        create_palo_object(args, logger, new_service_group, 'ServiceGroup', tree, device, devtype, failures)

def create_palo_tag(args, logger, new_tag, tags, devtype, tree, device, failures):

    # takes a Tag object 'new_tag' and checks dependencies etc...
    # note its important here to compare same types. set contains <class 'str'> so use a.name as that is also a <class 'str'>

    if not args.no_checks:
        # check not already existing
        if new_tag.name not in tags:
            create_palo_object(args, logger, new_tag, 'Tag', tree, device, devtype, failures)
        else:
            logger.warn("{} \'{}\': Not attempting to create Tag \'{}\'. Already exists! Skipping...".format(devtype, device, new_tag))
    else:
        create_palo_object(args, logger, new_tag, 'Tag', tree, device, devtype, failures)

def create_palo_dip(args, logger, new_dip, dips, devtype, tree, device, failures):

    # takes a Dip object and checks dependencies etc...

    if not args.no_checks:
        # check not already existing
        if new_dip.name not in dips:
            create_palo_object(args, logger, new_dip, 'Dip', tree, device, devtype, failures)
        else:
            logger.warn("{} \'{}\': Not attempting to create Dip \'{}\'. Already exists! Skipping...".format(devtype, device, new_dip))
    else:
        create_palo_object(args, logger, new_dip, 'Dip', tree, device, devtype, failures)

def create_palo_objects(args, logger, dbedit_objects, live_objects, subclass, tree, device, devtype, failures):

    # takes list of 'dbedit objects' and list of 'live objects' and calls 'create_palo_object' if not existing

    if dbedit_objects:
        if not args.quiet:
            logger.info("{} \'{}\', dbedit create requests: {} = \'{}\'".format(devtype, device, subclass, len(dbedit_objects)))
        for d in dbedit_objects:
            if not args.no_checks:
                for l in live_objects:
                    # check if the live object matches the name and type of dbedit object (e.g. object already exists)
                    if d.name == l.name:
                        if subclass == 'AddressObject':
                            if issubclass(type(l), AddressObject):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'AddressGroup':
                            if issubclass(type(l), AddressGroup):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'ApplicationContainer':
                            if issubclass(type(l), ApplicationContainer):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'ApplicationFilter':
                            if issubclass(type(l), ApplicationFilter):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'ApplicationObject':
                            if issubclass(type(l), ApplicationObject):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'ApplicationGroup':
                            if issubclass(type(l), ApplicationGroup):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'ServiceObject':
                            if issubclass(type(l), ServiceObject):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'ServiceGroup':
                            if issubclass(type(l), ServiceGroup):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'Tag':
                            if issubclass(type(l), Tag):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'Dip':
                            if issubclass(type(l), Dip):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'StaticRoute':
                            if issubclass(type(l), StaticRoute):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'SecurityRule':
                            if issubclass(type(l), SecurityRule):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        elif subclass == 'NatRule':
                            if issubclass(type(l), NatRule):
                                logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Already exists! Skipping...".format(devtype, device, subclass, d.name))
                                break
                        else:
                            logger.warn("{} \'{}\': Not attempting to create {} \'{}\'. Unknown subclass but name already used! Skipping...".format(devtype, device, subclass, d.name))
                            continue
                else:
                    # object does not already exist
                    create_palo_object(args, logger, d, subclass, tree, device, devtype, failures)
            else:
                create_palo_object(args, logger, d, subclass, tree, device, devtype, failures)
        else:
            logger.warn("{} \'{}\': No objects of type \'{}\' to create.".format(devtype, device, subclass))

def create_palo_object(args, logger, object, subclass, tree, device, devtype, failures):

    # takes a single object and creates as directed attaching to 'tree' in the process

    if object:
        if args.test:
            if not args.quiet:
                logger.info("{} \'{}\': TEST MODE - not creating {} \'{}\'. TEST!".format(devtype, device, subclass, object.name))
        else:
            if not args.quiet:
                logger.info("{} \'{}\': creating {} \'{}\'...".format(devtype, device, subclass, object.name))
            if subclass == 'Dip':
                try:
                    tree.userid.register(object.ip, object.tag)
                except Exception as e:
                    logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))
                    failures.add(object.name)
            else:
                tree.add(object)
                try:
                    object.create()
                except Exception as e:
                    logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))
                    failures.add(object.name)
    else:
        logger.warn("{} \'{}\': No object of type \'{}\' to create.".format(devtype, device, subclass))

def create_palo_route(args, logger, new_route, routes, devtype, tree, device, failures):

    # takes a StaticRoute object and checks dependencies etc...

    if not args.no_checks:
        if new_route.name not in routes:
            create_palo_object(args, logger, new_route, 'StaticRoute', tree, device, devtype, failures)
        else:
            logger.warn("{} \'{}\': Not attempting to create Tag \'{}\'. Already exists! Skipping...".format(devtype, device, new_route))
    else:
        create_palo_object(args, logger, new_route, 'StaticRoute', tree, device, devtype, failures)

####################################################################################
#
# Modify Functions
#
####################################################################################

def add_to_palo_group(args, logger, o, available_groups, available_members, devtype, subclass, tree, device, failures):

    # takes a ModifyGroup object 'o', finds it in the Tree per its Namespace (subclass) and calls 'add_member'
    # issue here is that you need the correct pandevice object in the tree in order to edit it.
    # second issue is that the object might not be in the tree so try to refresh it from live device

    group = tree.find(o.name, subclass)
    if not issubclass(type(group), subclass):
        # 'NoneType' returned from find method if object not in Tree - try to refresh it from live device
        group = subclass(o.name)
        tree.add(group)

    try:
        group.refresh()
        if issubclass(type(group), AddressGroup):
            existing_members = set(group.static_value)
        else:
            existing_members = set(group.value)

        for member in o.members:
            if member not in existing_members:
                add_palo_member(args, logger, o, group, member, devtype, device, failures)
            else:
                logger.warn("{} \'{}\': Member \'{}\' already in group \'{}\'! Skipping...".format(devtype, device, member, o.name))

    except Exception as e:
        logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))
        failures.add(o.name)
        logger.warn("{} \'{}\': Cannot add to group {} \'{}\'. FAILED!".format(devtype, device, str(type(group).__name__), o.name))

def add_palo_member(args, logger, o, group, member, devtype, device, failures):

    # tries to add member to group
    # removes placeholder objects if found

    try:
        if issubclass(type(group), AddressGroup):
            group.static_value.append(member)
        else:
            group.value.append(member)

        # remove placeholder objects
        if issubclass(type(group), AddressGroup):
            if len(group.static_value) > 1:
                for m in group.static_value:
                    if m == 'placeholder':
                        group.static_value.remove(m)
        elif issubclass(type(group), ServiceGroup):
            if len(group.value) > 1:
                for m in group.value:
                    if m == 'placeholder-service':
                        group.value.remove(m)

        # Use of 'create()' here simply changes the required variable.
        if not args.test:
            group.create()
            if not args.quiet:
                logger.info("{} \'{}\': Successfully added \'{}\' to group \'{}\'. OK!".format(devtype, device, member, o.name))
        else:
            if not args.quiet:
                logger.info("{} \'{}\': TEST MODE - not added \'{}\' to group \'{}\'. TEST!".format(devtype, device, member, o.name))

    except Exception as e:
                    logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))
                    failures.add(o.name)
                    logger.warn("{} \'{}\': Cannot add \'{}\' to group \'{}\'. FAILED!".format(devtype, device, member, o.name))

def remove_from_palo_group(args, logger, o, available_groups, available_members, devtype, subclass, tree, device, failures):

    # takes a ModifyGroup object 'o', finds it in the Tree per its Namespace (subclass) and calls 'remove_palo_member'
    # issue here is that you need the correct pandevice object in the tree in order to edit it.
    # second issue is that the object might not be in the tree so try to refresh it from live device

    group = tree.find(o.name, subclass)
    if not issubclass(type(group), subclass):
        # 'NoneType' returned from find method if object not in Tree - try to refresh it from live device
        group = subclass(o.name)
        tree.add(group)

    try:
        group.refresh()
        if issubclass(type(group), AddressGroup):
            existing_members = set(group.static_value)
        else:
            existing_members = set(group.value)

        for member in o.members:
            if member in existing_members:
                remove_palo_member(args, logger, o, group, member, available_members, tree, devtype, device, failures)
            else:
                logger.warn("{} \'{}\': Member \'{}\' not in group \'{}\'! Skipping...".format(devtype, device, member, o.name))

    except Exception as e:
        logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))
        failures.add(o.name)
        logger.warn("{} \'{}\': Cannot attempt to remove from group {} \'{}\'. FAILED!".format(devtype, device, str(type(group).__name__), o.name))

def remove_palo_member(args, logger, o, group, member, available_members, tree, devtype, device, failures):

    # tries to remove member from group
    # adds placeholder objects (creates if not found) so does not leave and empty group
    # empty ApplicationGroup = + ping
    # empty ServiceGroup = + placeholder-service (TCP port 0)
    # empty AddressGroup = + placeholder

    try:
        if issubclass(type(group), AddressGroup):
            group.static_value.remove(member)
        else:
            group.value.remove(member)

        # don't leave empty groups  - add placeholders
        if issubclass(type(group), AddressGroup):
            if len(group.static_value) == 0:
                if 'placeholder' not in available_members and not tree.find('placeholder', AddressObject):
                    p = AddressObject(name='placeholder', value='169.254.1.1', type='ip-netmask', description='placeholder object for empty groups')
                    create_palo_object(args, logger, p, 'AddressObject', tree, device, devtype, failures)
                group.static_value.append('placeholder')
        elif issubclass(type(group), ServiceGroup):
            if len(group.value) == 0:
                if 'placeholder-service' not in available_members:
                    p = ServiceObject(name='placeholder-service', protocol='tcp', destination_port=0, description='placeholder object for empty groups')
                    create_palo_object(args, logger, p, 'ServiceObject', tree, device, devtype, failures)
                group.value.append('placeholder-service')
        elif issubclass(type(group), ApplicationGroup):
            if len(group.value) == 0:
                group.value.append('ping')

        # use of apply() here pushes the altered group to the firewall, overwriting the existing group
        if not args.test:
            group.apply()
            if not args.quiet:
                logger.info("{} \'{}\': Successfully removed \'{}\' from group \'{}\'. OK!".format(devtype, device, member, o.name))
        else:
            if not args.quiet:
                logger.info("{} \'{}\': TEST MODE - not removed \'{}\' from group \'{}\'. TEST!".format(devtype, device, member, o.name))

    except Exception as e:
        logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))
        failures.add(o.name)
        logger.warn("{} \'{}\': Cannot remove \'{}\' from group \'{}\'. FAILED!".format(devtype, device, member, o.name))

####################################################################################
#
# Delete Functions
#
####################################################################################

def delete_palo_object(args, logger, o, object_names, devtype, subclass, tree, device, failures):

    # takes a DeleteObject object 'o', finds it in the Tree per its Namespace (objtype) and deletes it
    # issue here is that you need the correct pandevice object in the tree in order to delete it.
    # second issue is that the object might not be in the tree so try to refresh it from live device

    object = tree.find(o.name, subclass)
    if not issubclass(type(object), subclass):
        # 'NoneType' returned from find method if object not in Tree - try to refresh it from live device
        object = subclass(o.name)
        tree.add(object)

    try:
        object.refresh()

        # if object is a group then empty it first by setting members to empty list. Use of 'create()' here simply changes the one variable.
        if issubclass(type(object), AddressGroup):
            if object.static_value:
                object.static_value = list()
                if not args.test:
                    object.create()
        elif issubclass(type(object), ApplicationGroup):
            object.value = list()
            if not args.test:
                object.create()
        elif issubclass(type(object), ServiceGroup):
            object.value = list()
            if not args.test:
                object.create()

        if not args.test:
            object.delete()
            if not args.quiet:
                logger.info("{} \'{}\': Successfully deleted {} \'{}\'. OK!".format(devtype, device, str(type(object).__name__), o.name))
        else:
            if not args.quiet:
                logger.info("{} \'{}\': TEST MODE - not deleting {} \'{}\'. TEST!".format(devtype, device, str(type(object).__name__), o.name))
    except Exception as e:
        logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))
        failures.add(o.name)
        logger.warn("{} \'{}\': Cannot delete {} \'{}\'. FAILED!".format(devtype, device, str(type(object).__name__), o.name))

def delete_palo_dip(args, logger, o, existing_dip_names, devtype, tree, device, failures):

    # takes DIP object 'o' and unregisters ip/tag

    if args.test:
        if not args.quiet:
            logger.info("{} \'{}\': TEST MODE - not deleting DIP \'{}\'. TEST!".format(devtype, device, o.name))
    else:
        if not args.quiet:
            logger.info("{} \'{}\': deleting DIP \'{}\'...".format(devtype, device, o.name))
        try:
            tree.userid.unregister(ip=o.ip, tags=o.tag)

        except Exception as e:
            logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))
            failures.add(o.name)

####################################################################################
#
# Edit Functions
#
####################################################################################

def edit_palo_object(args, logger, o, object_names, devtype, subclass, tree, device, failures):

    # takes an EditObject object 'o' and finds the object in the tree before removing the 'name' and 'type' keys
    # If object found then adds all the key/values to edit and updates
    # if object not found, create an object of subclass and try to refresh it from the live device. If found then continue as above, else fail

    name = o.name
    object = tree.find(o.name, subclass)
    o.__dict__.pop('type', None)
    o.__dict__.pop('name', None)

    if not issubclass(type(object), subclass):
        # 'NoneType' returned from find method if object not in Tree - try to refresh it from live device
        object = subclass(name)
        tree.add(object)

    try:
        object.refresh()

        for key, value in o.__dict__.items():
            setattr(object, key, value)

        # Use of 'create()' here simply changes the variable set in setattr.
        if not args.test:
            object.create()
            if not args.quiet:
                logger.info("{} \'{}\': Successfully edited {} \'{}\'. OK!".format(devtype, device, o.type, name))
        else:
            if not args.quiet:
                logger.info("{} \'{}\': TEST MODE - not editing {} \'{}\'. TEST!".format(devtype, device, o.type, o.name))
    except Exception as e:
        logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))
        failures.add(name)
        logger.warn("{} \'{}\': Cannot edit {} \'{}\'. FAILED!".format(devtype, device, o.type, name))

####################################################################################
#
# DBedit functions
#
####################################################################################

def read_dbedit_csv(args, logger, filename, emails, email_subject, email_message, logfile):

    # parses a standard CSV format dbedit file and returns lists of Pandevice objects after syntax checking
    # does not yet have the ability to parse ApplicationFilter

    fields = ['vendor' , 'type' , 'op_action' , 'location' , 'name' , 'subtype' , 'members' , 'ip' , 'netmask' , 'cidr' , 'description' , 'color' , 'protocol' , 'source_port' , 'destination_port' , 'nexthop' , 'tag' , 'value' , 'interface' , 'enable_user_identification' , 'metric' , 'mgmt_profile' , 'zone' , 'rule_action' , 'application' , 'category' , 'data_filtering' , 'destination' , 'disable_server_response_inspection' , 'disabled' , 'file_blocking' , 'fromzone' , 'group' , 'hip_profiles' , 'icmp_unreachable' , 'log_end' , 'log_setting' , 'log_start' , 'negate_destination' , 'negate_source' , 'negate_target' , 'schedule' , 'service' , 'source' , 'source_user' , 'spyware' , 'target' , 'tozone' , 'url_filtering' , 'virus' , 'vulnerability' , 'wildfire_analysis' , 'destination_dynamic_translated_address' , 'destination_dynamic_translated_distribution' , 'destination_dynamic_translated_port' , 'destination_translated_address' , 'destination_translated_port' , 'ha_binding' , 'nat_type' , 'source_translation_address_type' , 'source_translation_fallback_interface' , 'source_translation_fallback_ip_address' , 'source_translation_fallback_ip_type' , 'source_translation_fallback_translated_addresses' , 'source_translation_fallback_type' , 'source_translation_interface' , 'source_translation_ip_address' , 'source_translation_static_bi_directional' , 'source_translation_static_translated_address' , 'source_translation_translated_addresses' , 'source_translation_type' , 'to_interface' , 'category' , 'subcategory' , 'technology' , 'risk' , 'evasive' , 'excessive_bandwidth_use' , 'prone_to_misuse' , 'is_saas' , 'transfers_files' , 'tunnels_other_apps' , 'used_by_malware' , 'has_known_vulnerabilities' , 'pervasive' , 'default_type' , 'parent_app' , 'timeout' , 'tcp_timeout' , 'udp_timeout' , 'tcp_half_closed_timeout' , 'tcp_time_wait_timeout' , 'tunnel_applications' , 'file_type_ident' , 'virus_ident' , 'data_ident' , 'default_port' , 'default_ip_protocol' , 'default_icmp_type' , 'default_icmp_code']
    csv_fields = 100

    # set the fixed values for the numbered CSV fields
    vendor = 0
    type = 1
    op_action = 2
    location = 3
    name = 4
    subtype = 5
    members = 6
    ip = 7
    netmask = 8
    cidr = 9
    description = 10
    color = 11
    protocol = 12
    source_port = 13
    destination_port = 14
    nexthop = 15
    tag = 16
    value = 17
    interface = 18
    enable_user_identification = 19
    metric = 20
    mgmt_profile = 21
    zone = 22
    rule_action = 23
    application = 24
    category = 25
    data_filtering = 26
    destination = 27
    disable_server_response_inspection = 28
    disabled = 29
    file_blocking = 30
    fromzone = 31
    group = 32
    hip_profiles = 33
    icmp_unreachable = 34
    log_end = 35
    log_setting = 36
    log_start = 37
    negate_destination = 38
    negate_source = 39
    negate_target = 40
    schedule = 41
    service = 42
    source = 43
    source_user = 44
    spyware = 45
    target = 46
    tozone = 47
    url_filtering = 48
    virus = 49
    vulnerability = 50
    wildfire_analysis = 51
    destination_dynamic_translated_address = 52
    destination_dynamic_translated_distribution = 53
    destination_dynamic_translated_port = 54
    destination_translated_address = 55
    destination_translated_port = 56
    ha_binding = 57
    nat_type = 58
    source_translation_address_type = 59
    source_translation_fallback_interface = 60
    source_translation_fallback_ip_address = 61
    source_translation_fallback_ip_type = 62
    source_translation_fallback_translated_addresses = 63
    source_translation_fallback_type = 64
    source_translation_interface = 65
    source_translation_ip_address = 66
    source_translation_static_bi_directional = 67
    source_translation_static_translated_address = 68
    source_translation_translated_addresses = 69
    source_translation_type = 70
    to_interface = 71
    category = 72
    subcategory = 73
    technology = 74
    risk = 75
    evasive = 76
    excessive_bandwidth_use = 77
    prone_to_misuse = 78
    is_saas = 79
    transfers_files = 80
    tunnels_other_apps = 81
    used_by_malware = 82
    has_known_vulnerabilities = 83
    pervasive = 84
    default_type = 85
    parent_app = 86
    timeout = 87
    tcp_timeout = 88
    udp_timeout = 89
    tcp_half_closed_timeout = 90
    tcp_time_wait_timeout = 91
    tunnel_applications = 92
    file_type_ident = 93
    virus_ident = 94
    data_ident = 95
    default_port = 96
    default_ip_protocol = 97
    default_icmp_type = 98
    default_icmp_code = 99

    nested_dict = lambda: defaultdict(nested_dict)
    dbedit_processed_objects = nested_dict()

    nested_dict_pre = lambda: defaultdict(nested_dict)
    dbedit_processed_pre_rules = nested_dict_pre()

    nested_dict_post = lambda: defaultdict(nested_dict)
    dbedit_processed_post_rules = nested_dict_post()

    t = today.strftime('%Y-%m-%d')
    auto_description = ('CREATED by API: ' + t)

    # Opening a file with the mode 'U' or 'rU' will open a file for reading in universal newline mode
    try:
        with open(filename, 'rU', newline='', encoding='utf-8') as f:

            ###############################################################################
            #
            # in order to skip commented lines you have to do this before csv.reader sees the file as it would otherwise parse it out.
            # good example of python failing here
            #
            ###############################################################################

            reader = csv.reader(decomment(f, args, logger))

            for row in reader:

                ###############################################################################
                #
                # We need to create proper var types from CSV else pandevice will barf - also update comment/desc field
                #
                ###############################################################################

                if row[op_action] == 'edit':
                    auto_description = ('EDITED by API: ' + t)

                if row[op_action] == 'addtogroup' or row[op_action] == 'removefromgroup':
                    auto_description = ('MODIFIED by API: ' + t)

                if row[description]:
                    row[description] += ' - ' + auto_description
                else:
                    row[description] = auto_description

                if row[members]:
                    row[members] = make_list_from_str(row[members])
                else:
                    row[members] = None

                if row[tag]:
                    row[tag] = make_list_from_str(row[tag])
                else:
                    row[tag] = None

                if '__' in row[location]:
                    row[location] = row[location].split('__')[0]

                for n in range(5, csv_fields):
                    if row[n] in ['FALSE', 'False', 'false']:
                        row[n] = False 
                    elif row[n] in ['TRUE', 'True', 'true']:
                        row[n] = True 

                ###############################################################################
                #
                # Palo vendor section
                #
                ###############################################################################

                if row[vendor] == 'palo':

                    nattypes = ['nat-rule', 'pre-nat-rule', 'post-nat-rule']
                    ruletypes = ['security-rule', 'pre-security-rule', 'post-security-rule']

                    # initialise 'o'
                    o = None
                    if args.verbose:
                        logger.info('dbedit: Found vendor \'{}\', location \'{}\', action \'{}\', type \'{}\' processing...'.format(row[vendor], row[location], row[op_action], row[type]))

                    # ensure that the object at 'row[type]' is a list otherwise you will get an error about append
                    if not dbedit_processed_objects[row[vendor]][row[location]][row[op_action]][row[type]]:
                        dbedit_processed_objects[row[vendor]][row[location]][row[op_action]][row[type]] = list()

                    if not dbedit_processed_pre_rules[row[vendor]][row[location]][row[op_action]][row[type]]:
                        dbedit_processed_pre_rules[row[vendor]][row[location]][row[op_action]][row[type]] = list()

                    if not dbedit_processed_post_rules[row[vendor]][row[location]][row[op_action]][row[type]]:
                        dbedit_processed_post_rules[row[vendor]][row[location]][row[op_action]][row[type]] = list()

                    # check type and create object of 'type' provided
                    if row[op_action] == 'delete':
                        if row[type] == 'dip':
                            if check_dbedit_syntax_palo_dip(row[op_action], row[members], row[tag], args):
                                o = Dip(ip=row[members], tag=row[tag])
                            else:
                                logger.warn('dbedit: junk syntax for Dip \'{}#{}#{}\', skipping...'.format(row[op_action], row[ip], row[tag]))
                        else:
                            o = DeleteObject(name=row[name], type=row[type])
                    elif row[op_action] == 'edit':
                        fields_to_edit = dict()
                        # do all the string-to-list conversions
                        if row[application]:
                            row[application] = make_list_from_str(row[application])
                        if row[category]:
                            row[category] = make_list_from_str(row[category])
                        if row[destination]:
                            row[destination] = make_list_from_str(row[destination])
                        if row[fromzone]:
                            row[fromzone] = make_list_from_str(row[fromzone])
                        if row[hip_profiles]:
                            row[hip_profiles] = make_list_from_str(row[hip_profiles])
                        if row[source]:
                            row[source] = make_list_from_str(row[source])
                        if row[source_user]:
                            row[source_user] = make_list_from_str(row[source_user])
                        if row[target]:
                            row[target] = make_list_from_str(row[target])
                        if row[tozone]:
                            row[tozone] = make_list_from_str(row[tozone])
                        if row[source_translation_fallback_translated_addresses]:
                            row[source_translation_fallback_translated_addresses] = make_list_from_str(row[source_translation_fallback_translated_addresses])
                        if row[source_translation_translated_addresses]:
                            row[source_translation_translated_addresses] = make_list_from_str(row[source_translation_translated_addresses])
                        if row[tunnel_applications]:
                            row[tunnel_applications] = make_list_from_str(row[tunnel_applications])
                        if row[default_port]:
                            row[default_port] = make_list_from_str(row[default_port])
                        # tidy up some exceptions here, where value does not match csv exactly...
                        if row[service]:
                            if row[type] in nattypes:
                                # for Nats, service is str type! extract str from ['G_TCP-7']
                                try:
                                    m = re.search("'(.+?)'", row[service]).group(1)
                                except AttributeError:
                                    m = ''
                                row[service] = m
                            else:
                                row[service] = make_list_from_str(row[service])
                        if row[type] == 'address-group':
                            if row[subtype] == 'dynamic':
                                    # dynamic groups use row[value] field but pandevice uses 'dynamic_value' - make sure its in the correct format for the Palo filter condition e.g. 'x55MGMT-SMAT1-ONBOARDING_TAG' and 'x55MGMT-FAKE1-ONBOARDING_TAG'
                                    if row[value]:
                                        row[value] = make_list_from_str(row[value])
                                        if len(row[value]) > 0:
                                            str = '\' and \''.join(row[value])
                                            fields_to_edit['dynamic_value'] = "'" + str + "'"
                                            row[value] = ""
                            if row[subtype] == 'static':
                                # static groups use row[members] field but pandevice uses 'static_value'
                                if row[members]:
                                    fields_to_edit['static_value'] = row[members]
                                    row[members] = ""
                        if row[type] == 'address':
                            if row[subtype] == 'ip-netmask':
                                row[value] = row[cidr]
                                row[cidr] = ""
                        if row[type] == 'service-group':
                            # service groups use row[members] field but pandevice uses 'value'
                            if row[members]:
                                row[value] = row[members]
                                row[members] = ""
                        if row[type] == 'tag':
                            # tags use row[description] field but pandevice uses 'comment'
                            if row[description]:
                                fields_to_edit['comments'] = row[description]
                                row[description] = ""
                        if row[type] == 'route':
                            # route uses the following
                            if row[cidr]:
                                row[destination] = row[cidr]
                                row[cidr] = ""
                            if row[subtype]:
                                fields_to_edit['nexthop_type'] = row[subtype]
                                row[subtype] = ""
                            if row[value]:
                                fields_to_edit['admin_dist'] = row[value]
                                row[value] = ""
                        if row[type] == 'application':
                            # application uses the following
                            if row[evasive]:
                                fields_to_edit['evasive_behavior'] = row[evasive]
                                row[evasive] = ""
                            if row[excessive_bandwidth_use]:
                                fields_to_edit['consume_big_bandwidth'] = row[excessive_bandwidth_use]
                                row[excessive_bandwidth_use] = ""
                            if row[transfers_files]:
                                fields_to_edit['able_to_transfer_file'] = row[transfers_files]
                                row[transfers_files] = ""
                            if row[has_known_vulnerabilities]:
                                fields_to_edit['has_known_vulnerability'] = row[has_known_vulnerabilities]
                                row[has_known_vulnerabilities] = ""
                            if row[tunnels_other_apps]:
                                fields_to_edit['tunnel_other_application'] = row[tunnels_other_apps]
                                row[tunnels_other_apps] = ""
                            if row[pervasive]:
                                fields_to_edit['pervasive_use'] = row[pervasive]
                                row[pervasive] = ""
                        if row[type] == 'application-group':
                            # application groups use row[members] field but pandevice uses 'value'
                            if row[members]:
                                row[value] = row[members]
                                row[members] = ""
                        if row[type] in ruletypes:
                            if row[rule_action]:
                                fields_to_edit['action'] = row[rule_action]
                                row[rule_action] = ""
                        fields_to_edit['name'] = row[name]
                        fields_to_edit['type'] = row[type]
                        for n in range(5, csv_fields):
                            if row[n]:
                                fields_to_edit[fields[n]] = row[n]
                        o = EditObject(**fields_to_edit)
                    elif row[op_action] == 'addtogroup':
                        o = ModifyGroup(name=row[name], type=row[type], members=row[members], action=row[op_action], description=row[description])
                    elif row[op_action] == 'removefromgroup':
                        o = ModifyGroup(name=row[name], type=row[type], members=row[members], action=row[op_action], description=row[description])
                    elif row[type] == 'address':
                        # make address object
                        if check_dbedit_syntax_palo_address(row[name], row[description], row[tag], row[subtype], row[value], row[ip], row[cidr], args):
                            if row[subtype] == 'ip-netmask':
                                o = AddressObject(name=row[name], value=row[cidr], type=row[subtype], description=row[description], tag=row[tag])
                            if row[subtype] == 'fqdn':
                                o = AddressObject(name=row[name], value=row[value], type=row[subtype], description=row[description], tag=row[tag])
                            if row[subtype] == 'ip-range':
                                o = AddressObject(name=row[name], value=row[value], type=row[subtype], description=row[description], tag=row[tag])
                        else:
                            logger.warn('dbedit: junk syntax for AddressObject \'{}#{}#{}#{}#{}#{}#{}\', skipping...'.format(row[name], row[description], row[tag], row[subtype], row[value], row[ip], row[cidr]))
                    elif row[type] == 'address-group':
                        # make address-group object
                        if check_dbedit_syntax_palo_addressgroup(row[name], row[description], row[subtype], row[tag], row[members], row[value], args):
                            if row[subtype] == 'dynamic':
                                # dynamic groups use row[value] field - make sure its in the correct format for the Palo filter condition e.g. 'x55MGMT-SMAT1-ONBOARDING_TAG' and 'x55MGMT-FAKE1-ONBOARDING_TAG'
                                if row[value]:
                                    row[value] = make_list_from_str(row[value])
                                    if len(row[value]) > 0:
                                        str = '\' and \''.join(row[value])
                                        row[value] = "'" + str + "'"
                                o = AddressGroup(name=row[name], description=row[description], dynamic_value=row[value], tag=row[tag])
                            elif row[subtype] == 'static':
                                if row[members] is None:
                                    row[members] = ['placeholder']
                                o = AddressGroup(name=row[name], description=row[description], static_value=row[members], tag=row[tag])
                        else:
                            logger.warn('dbedit: junk syntax for AddressGroup \'{}#{}#{}#{}\', skipping...'.format(row[name], row[description], row[tag], row[members]))
                    elif row[type] == 'service':
                        # make service object
                        if not row[source_port]:
                            row[source_port] = None
                        if check_dbedit_syntax_palo_service(row[name], row[protocol], row[source_port], row[destination_port], row[description], row[tag], args):
                            o = ServiceObject(name=row[name], protocol=row[protocol], source_port=row[source_port], destination_port=row[destination_port], description=row[description], tag=row[tag])
                        else:
                            logger.warn('dbedit: junk syntax for ServiceObject \'{}#{}#{}#{}#{}#{}\', skipping...'.format(row[name], row[protocol], row[source_port], row[destination_port], row[description], row[tag]))
                    elif row[type] == 'service-group':
                        # make service-group object
                        if check_dbedit_syntax_palo_servicegroup(row[name], row[members], row[tag], args):
                            o = ServiceGroup(name=row[name], value=row[members], tag=row[tag])
                        else:
                            logger.warn('dbedit: junk syntax for ServiceGroup \'{}#{}#{}\', skipping...'.format(row[name], row[members], row[tag]))
                    elif row[type] == 'tag':
                        # make tag object
                        if not row[color]:
                            row[color] = None
                        if check_dbedit_syntax_palo_tag(row[name], row[description], args):
                            o = Tag(name=row[name], comments=row[description], color=row[color])
                        else:
                            logger.warn('dbedit: junk syntax for Tag \'{}#{}#{}\', skipping...'.format(row[name], row[description], row[color]))
                    elif row[type] == 'dip':
                        # make dip object after syntax checking
                        if check_dbedit_syntax_palo_dip(row[op_action], row[members], row[tag], args):
                            o = Dip(ip=row[members], tag=row[tag])
                        else:
                            logger.warn('dbedit: junk syntax for Dip \'{}#{}#{}\', skipping...'.format(row[op_action], row[ip], row[tag]))
                    elif row[type] == 'route':
                        # make route object
                        if not row[interface]:
                            row[interface] = None
                        if not row[metric]:
                            # set metric to default of 10 if not provided.
                            row[metric] = 10
                        else:
                            row[metric] = int(row[metric])
                        if not row[value] or row[value] == 'default':
                            # set value to default of 10 if not provided.
                            row[value] = 10
                        else:
                            row[value] = int(row[value])
                        if check_dbedit_syntax_palo_route(row[name], row[cidr], row[subtype], row[nexthop], row[interface], row[value], row[metric], args):
                            o = StaticRoute(name=row[name], destination=row[cidr], nexthop_type=row[subtype], nexthop=row[nexthop], interface=row[interface], admin_dist=row[value], metric=row[metric])
                        else:
                            logger.warn('dbedit: junk syntax for Route \'{}#{}#{}#{}#{}#{}#{}\', skipping...'.format(row[name], row[cidr], row[subtype], row[nexthop], row[interface], row[value], row[metric]))
                    elif row[type] == 'application':
                        # make application object
                        if row[tunnel_applications]:
                            row[tunnel_applications] = make_list_from_str(row[tunnel_applications])
                        else:
                            row[tunnel_applications] = None
                        if row[default_port]:
                            row[default_port] = make_list_from_str(row[default_port])
                        else:
                            row[default_port] = None
                        if not row[parent_app]:
                            row[parent_app] = None
                        if not row[timeout]:
                            row[timeout] = None
                        else:
                            row[timeout] = int(row[timeout])
                        if not row[tcp_timeout]:
                            row[tcp_timeout] = None
                        else:
                            row[tcp_timeout] = int(row[tcp_timeout])
                        if not row[udp_timeout]:
                            row[udp_timeout] = None
                        else:
                            row[udp_timeout] = int(row[udp_timeout])
                        if not row[tcp_half_closed_timeout]:
                            row[tcp_half_closed_timeout] = None
                        else:
                            row[tcp_half_closed_timeout] = int(row[tcp_half_closed_timeout])
                        if not row[tcp_time_wait_timeout]:
                            row[tcp_time_wait_timeout] = None
                        else:
                            row[tcp_time_wait_timeout] = int(row[tcp_time_wait_timeout])
                        if not row[risk]:
                            row[risk] = None
                        else:
                            row[risk] = int(row[risk])
                        if not row[default_ip_protocol]:
                            row[default_ip_protocol] = None
                        if not row[default_icmp_type]:
                            row[default_icmp_type] = None
                        if not row[default_icmp_code]:
                            row[default_icmp_code] = None

                        if check_dbedit_syntax_palo_application(row[name], row[category], row[subcategory], row[technology], row[risk], args):
                            o = ApplicationObject(name=row[name], description=row[description], category=row[category], subcategory=row[subcategory], technology=row[technology], risk=int(row[risk]), \
                                                  default_type=row[default_type], default_port=row[default_port], default_ip_protocol=row[default_ip_protocol], default_icmp_type=row[default_icmp_type], \
                                                  default_icmp_code=row[default_icmp_code], parent_app=row[parent_app], timeout=row[timeout], tcp_timeout=row[tcp_timeout], udp_timeout=row[udp_timeout], \
                                                  tcp_half_closed_timeout=row[tcp_half_closed_timeout], tcp_time_wait_timeout=row[tcp_time_wait_timeout], evasive_behavior=row[evasive], \
                                                  consume_big_bandwidth=row[excessive_bandwidth_use], used_by_malware=row[used_by_malware], able_to_transfer_file=row[transfers_files], \
                                                  has_known_vulnerability=row[has_known_vulnerabilities], tunnel_other_application=row[tunnels_other_apps], tunnel_applications=row[tunnel_applications], \
                                                  prone_to_misuse=row[prone_to_misuse], pervasive_use=row[pervasive], file_type_ident=row[file_type_ident], virus_ident=row[virus_ident], \
                                                  data_ident=row[data_ident], tag=row[tag])
                        else:
                            logger.warn('dbedit: junk syntax for ApplicationObject \'{}\', skipping...'.format(row[name]))
                    elif row[type] == 'application-group':
                        # make application-group object
                        if check_dbedit_syntax_palo_application_group(row[name], row[members], args):
                            o = ApplicationGroup(name=row[name], value=row[members], tag=row[tag])
                        else:
                            logger.warn('dbedit: junk syntax for ApplicationGroup \'{}#{}\', skipping...'.format(row[name], row[members]))
                    elif row[type] in ruletypes:
                        # make security-rule object
                        # as rule has no 'position' attribute new rules are automatically added to the end of the policy

                        # for all the list types convert to list or ['any'] if empty ('tag' done above)
                        if row[application]:
                            row[application] = make_list_from_str(row[application])
                        else:
                            row[application] = ['any']

                        if row[category]:
                            row[category] = make_list_from_str(row[category])
                        else:
                            row[category] = ['any']

                        if row[destination]:
                            row[destination] = make_list_from_str(row[destination])
                        else:
                            row[destination] = ['any']

                        if row[fromzone]:
                            row[fromzone] = make_list_from_str(row[fromzone])
                        else:
                            row[fromzone] = ['any']

                        if row[hip_profiles]:
                            row[hip_profiles] = make_list_from_str(row[hip_profiles])
                        else:
                            row[hip_profiles] = ['any']

                        if row[service]:
                            row[service] = make_list_from_str(row[service])
                        else:
                            row[service] = ['application-default']

                        if row[source]:
                            row[source] = make_list_from_str(row[source])
                        else:
                            row[source] = ['any']

                        if row[source_user]:
                            row[source_user] = make_list_from_str(row[source_user])
                        else:
                            row[source_user] = ['any']

                        if row[target]:
                            row[target] = make_list_from_str(row[target])
                        else:
                            row[target] = None

                        if row[tozone]:
                            row[tozone] = make_list_from_str(row[tozone])
                        else:
                            row[tozone] = ['any']

                        # for mandatory empty types set to specific value

                        if not row[subtype]:
                            row[subtype] = 'universal'

                        # for all the boolean types set to False if not set to True (subtle difference here)
                        if row[disabled] is not True:
                            row[disabled] = False
                        if row[icmp_unreachable] is not True:
                            row[icmp_unreachable] = False
                        if row[log_end] is not True:
                            row[log_end] = False
                        if row[log_start] is not True:
                            row[log_start] = False
                        if row[negate_destination] is not True:
                            row[negate_destination] = False
                        if row[negate_source] is not True:
                            row[negate_source] = False
                        if row[negate_target] is not True:
                            row[negate_target] = False
                        if row[disable_server_response_inspection] is not True:
                            row[disable_server_response_inspection] = False

                       # for all the str types set to None if no value given
                        if not row[data_filtering]:
                            row[data_filtering] = None
                        if not row[description]:
                            row[description] = None
                        if not row[file_blocking]:
                            row[file_blocking] = None
                        if not row[group]:
                            row[group] = None
                        if not row[log_setting]:
                            row[log_setting] = None
                        if not row[schedule]:
                            row[schedule] = None
                        if not row[spyware]:
                            row[spyware] = None
                        if not row[url_filtering]:
                            row[url_filtering] = None
                        if not row[virus]:
                            row[virus] = None
                        if not row[vulnerability]:
                            row[vulnerability] = None
                        if not row[wildfire_analysis]:
                            row[wildfire_analysis] = None

                        if check_dbedit_syntax_palo_security_rule(row[name], row[rule_action], row[subtype], row[description], args):
                            o = SecurityRule(name=row[name], \
                                             action=row[rule_action], \
                                             application=row[application], \
                                             category=row[category], \
                                             data_filtering=row[data_filtering], \
                                             description=row[description], \
                                             destination=row[destination], \
                                             disable_server_response_inspection=row[disable_server_response_inspection], \
                                             disabled=row[disabled], \
                                             file_blocking=row[file_blocking], \
                                             fromzone=row[fromzone], \
                                             group=row[group], \
                                             hip_profiles=row[hip_profiles], \
                                             icmp_unreachable=row[icmp_unreachable], \
                                             log_end=row[log_end], \
                                             log_setting=row[log_setting], \
                                             log_start=row[log_start], \
                                             negate_destination=row[negate_destination], \
                                             negate_source=row[negate_source], \
                                             negate_target=row[negate_target],  \
                                             schedule=row[schedule], \
                                             service=row[service], \
                                             source=row[source], \
                                             source_user=row[source_user], \
                                             spyware=row[spyware], \
                                             tag=row[tag], \
                                             target=row[target], \
                                             tozone=row[tozone], \
                                             type=row[subtype], \
                                             url_filtering=row[url_filtering], \
                                             virus=row[virus], \
                                             vulnerability=row[vulnerability], \
                                             wildfire_analysis=row[wildfire_analysis])
                        else:
                            logger.warn('dbedit: junk syntax for SecurityRule \'{}#{}#{}#{}\', skipping...'.format(row[name], row[rule_action], row[subtype], row[description]))
                    elif row[type] in nattypes:
                        # make nat-rule object
                        # Force disabled to True
                        # as rule has no 'position' attribute new rules are automatically added to the end of the policy

                        # for all the list types convert to list or ['any'] if empty ('tag' done above)
                        if row[destination]:
                            row[destination] = make_list_from_str(row[destination])
                        else:
                            row[destination] = ['any']

                        if row[fromzone]:
                            row[fromzone] = make_list_from_str(row[fromzone])
                        else:
                            row[fromzone] = ['any']

                        if row[source]:
                            row[source] = make_list_from_str(row[source])
                        else:
                            row[source] = ['any']

                        if row[source_translation_fallback_translated_addresses]:
                            row[source_translation_fallback_translated_addresses] = make_list_from_str(row[source_translation_fallback_translated_addresses])
                        else:
                            row[source_translation_fallback_translated_addresses] = None

                        if row[source_translation_translated_addresses]:
                            row[source_translation_translated_addresses] = make_list_from_str(row[source_translation_translated_addresses])
                        else:
                            row[source_translation_translated_addresses] = None

                        if row[target]:
                            row[target] = make_list_from_str(row[target])
                        else:
                            row[target] = None

                        if row[tozone]:
                            row[tozone] = make_list_from_str(row[tozone])
                        else:
                            row[tozone] = None

                        # for all the boolean types set to False if not set to True (subtle difference here)
                        if row[disabled] is not True:
                            row[disabled] = False
                        if row[negate_target] is not True:
                            row[negate_target] = False
                        if row[source_translation_static_bi_directional] is not True:
                            row[source_translation_static_bi_directional] = False

                        # for all the empty str types set to None
                        if not row[description]:
                            row[description] = None
                        if not row[destination_dynamic_translated_address]:
                            row[destination_dynamic_translated_address] = None
                        if not row[destination_dynamic_translated_distribution]:
                            row[destination_dynamic_translated_distribution] = None
                        if not row[destination_translated_address]:
                            row[destination_translated_address] = None
                        if not row[ha_binding]:
                            row[ha_binding] = None
                        if not row[nat_type]:
                            row[nat_type] = None
                        if not row[service]:
                            row[service] = 'any'
                        if not row[source_translation_address_type]:
                            row[source_translation_address_type] = None
                        if not row[source_translation_fallback_interface]:
                            row[source_translation_fallback_interface] = None
                        if not row[source_translation_fallback_ip_address]:
                            row[source_translation_fallback_ip_address] = None
                        if not row[source_translation_fallback_ip_type]:
                            row[source_translation_fallback_ip_type] = None
                        if not row[source_translation_fallback_type]:
                            row[source_translation_fallback_type] = None
                        if not row[source_translation_interface]:
                            row[source_translation_interface] = None
                        if not row[source_translation_ip_address]:
                            row[source_translation_ip_address] = None
                        if not row[source_translation_static_translated_address]:
                            row[source_translation_static_translated_address] = None
                        if not row[source_translation_type]:
                            row[source_translation_type] = None
                        if not row[interface]:
                            row[interface] = None

                        # for all the empty int types set to None
                        if not row[destination_translated_port]:
                            row[destination_translated_port] = None
                        if not row[destination_dynamic_translated_port]:
                            row[destination_dynamic_translated_port] = None

                        if check_dbedit_syntax_palo_nat_rule(row[name], row[description], row[tozone], args):
                            o = NatRule(name=row[name], \
                                             description=row[description], \
                                             destination=row[destination], \
                                             destination_dynamic_translated_address=row[destination_dynamic_translated_address], \
                                             destination_dynamic_translated_distribution=row[destination_dynamic_translated_distribution], \
                                             destination_dynamic_translated_port=row[destination_dynamic_translated_port], \
                                             destination_translated_address=row[destination_translated_address], \
                                             destination_translated_port=row[destination_translated_port], \
                                             disabled=row[disabled], \
                                             fromzone=row[fromzone], \
                                             ha_binding=row[ha_binding], \
                                             nat_type=row[nat_type], \
                                             negate_target=row[negate_target], \
                                             service=row[service], \
                                             source=row[source], \
                                             source_translation_address_type=row[source_translation_address_type], \
                                             source_translation_fallback_interface=row[
                                                 source_translation_fallback_interface], \
                                             source_translation_fallback_ip_address=row[
                                                 source_translation_fallback_ip_address], \
                                             source_translation_fallback_ip_type=row[source_translation_fallback_ip_type], \
                                             source_translation_fallback_translated_addresses=row[
                                                 source_translation_fallback_translated_addresses], \
                                             source_translation_fallback_type=row[source_translation_fallback_type], \
                                             source_translation_interface=row[source_translation_interface], \
                                             source_translation_ip_address=row[source_translation_ip_address], \
                                             source_translation_static_bi_directional=row[
                                                 source_translation_static_bi_directional], \
                                             source_translation_static_translated_address=row[
                                                 source_translation_static_translated_address], \
                                             source_translation_translated_addresses=row[
                                                 source_translation_translated_addresses], \
                                             source_translation_type=row[source_translation_type], \
                                             tag=row[tag], \
                                             target=row[target], \
                                             to_interface=row[interface], \
                                             tozone=row[tozone])
                        else:
                            logger.warn('dbedit: junk syntax for NatRule \'{}#{}#{}\', skipping...'.format(row[name], row[description], row[tozone]))
                    else:
                        logger.warn('dbedit: Unsupported type \'{}\', (contact your nearest Security Engineering resource). skipping...'.format(row[type]))

                    ###############################################################################
                    #
                    # add more elif statements here as new dbedit types are added
                    #
                    ###############################################################################

                    # append object 'o' to list
                    if o is not None:
                        # you will have to return a different set of objects here for pre/post-rules as no way to differentiate later
                        if row[op_action] == 'delete':
                            dbedit_processed_objects[row[vendor]][row[location]][row[op_action]][row[type]].append(o)
                        elif row[op_action] == 'edit':
                            dbedit_processed_objects[row[vendor]][row[location]][row[op_action]][row[type]].append(o)
                        elif row[op_action] == 'addtogroup':
                            dbedit_processed_objects[row[vendor]][row[location]][row[op_action]][row[type]].append(o)
                        elif row[op_action] == 'removefromgroup':
                            dbedit_processed_objects[row[vendor]][row[location]][row[op_action]][row[type]].append(o)
                        elif row[type] == 'pre-security-rule':
                            dbedit_processed_pre_rules[row[vendor]][row[location]][row[op_action]][row[type]].append(o)
                        elif row[type] == 'pre-nat-rule':
                            dbedit_processed_pre_rules[row[vendor]][row[location]][row[op_action]][row[type]].append(o)
                        if row[type] == 'post-security-rule':
                            dbedit_processed_post_rules[row[vendor]][row[location]][row[op_action]][row[type]].append(o)
                        elif row[type] == 'post-nat-rule':
                            dbedit_processed_post_rules[row[vendor]][row[location]][row[op_action]][row[type]].append(o)
                        else:
                            dbedit_processed_objects[row[vendor]][row[location]][row[op_action]][row[type]].append(o)
        f.close()

    except Exception as e:
        logger.error("{}. Exiting...".format(neutralise_newlines(repr(e), args, logger)))
        for email in emails:
            send_email(email_subject, email + __email_domain__, logfile, email_message, args, logger)
        sys.exit(1)

    # return our list of dbedit object that passed syntax checking
    return dbedit_processed_objects, dbedit_processed_pre_rules, dbedit_processed_post_rules

def check_dbedit_syntax_palo_address(name, description, tag, subtype, value, ip, cidr, args):

    # name (str) – Name of the object
    # value (str) – IP address or other value of the object
    # subtype (str) – Type of address: * ip-netmask (default) * ip-range * fqdn
    # description (str) – Description of this object
    # tag (list) – Administrative tags

    if args.no_checks:
        return True
    else:
        types = ['ip-netmask', 'fqdn', 'ip-range']

        # check if actual IPs are supplied in range
        if '-' in value:
            values = value.split('-')
            if check_ip(values[0]):
                if check_ip(values[1]):
                    pass
                else:
                    return False
            else:
                return False

        if check_max_length(name, 63):
            if check_max_length(description, 255):
                if tag is None or check_max_length(tag, 31):
                    if subtype in types:
                        if not ip or check_ip(ip):
                            if not cidr or check_cidr(cidr):
                                if not value or '.' in value:
                                    if ip is not None and cidr is not None and value is not None:
                                        return True

        return False

def check_dbedit_syntax_palo_addressgroup(name, description, subtype, tags, members, filter, args):

    # static_value (list) – Values for a static address group
    # dynamic_value (str) – Registered-ip tags for a dynamic address group
    # description (str) – Description of this object
    # tag (list) – Administrative tags (not to be confused with registered-ip tags)
    # members (list)

    if args.no_checks:
        return True
    else:
        types = ['dynamic', 'static']

        if subtype in types:
            if check_max_length(name, 63):
                if check_max_length(description, 255):
                    if tags:
                        for t in tags:
                            if not check_max_length(t, 31):
                                return False
                        else:
                            if subtype == 'dynamic':
                                if check_max_length(filter, 31):
                                    return True
                            elif members:
                                for member in members:
                                    if not check_max_length(member, 63):
                                        return False
                                else:
                                    return True
                    else:
                        if subtype == 'dynamic':
                            if check_max_length(filter, 31):
                                return True
                        elif members:
                            for member in members:
                                if not check_max_length(member, 63):
                                    return False
                            else:
                                return True

        return False

def check_dbedit_syntax_palo_service(name, protocol, source_port, destination_port, description, tags, args):

    # name (str) – Name of the object
    # protocol (str) – Protocol of the service, either tcp or udp
    # source_port (str) – Source port of the protocol, if any
    # destination_port (str) – Destination port of the service
    # description (str) – Description of this object
    # tag (list) – Administrative tags
    # check if ports are ranges or not
    # Port can be a single port, range (1-65535), or comma separated (80, 8080, 443) - need to allow for list here

    if args.no_checks:
        return True
    else:

        if source_port is not None:
            if '-' in source_port:
                source_ports = source_port.split('-')
                if 1 <= int(source_ports[0]) <= 65535:
                    if 1 <= int(source_ports[1]) <= 65535:
                        if int(source_ports[0]) != int(source_ports[1]):
                            pass
                        else:
                            return False
                    else:
                        return False
                else:
                    return False
            else:
                source_port = int(source_port)
                if 1 <= source_port <= 65535:
                    pass
                else:
                    return False

        if destination_port is not None:
            if '-' in destination_port:
                destination_ports = destination_port.split('-')
                if 1 <= int(destination_ports[0]) <= 65535:
                    if 1 <= int(destination_ports[1]) <= 65535:
                        if int(destination_ports[0]) != int(destination_ports[1]):
                            pass
                        else:
                            return False
                    else:
                        return False
                else:
                    return False
            else:
                destination_port = int(destination_port)
                if 1 <= destination_port <= 65535:
                        pass
                else:
                    return False
        else:
            return False

        if check_max_length(name, 63):
            if check_max_length(description, 255):
                # requires the double () here to check more than one pattern
                if protocol.startswith(('tcp', 'udp')):
                    if tags is not None:
                        for tag in tags:
                            if not check_max_length(tag, 31):
                                return False
                        else:
                            return True
                    else:
                        return True

        return False

def check_dbedit_syntax_palo_servicegroup(name, members, tags, args):

    # name (str) – Name of the object
    # members (list) – List of service values
    # tag (list) – Administrative tags

    if args.no_checks:
        return True
    else:
        if check_max_length(name, 63):
            if tags:
                for tag in tags:
                    if not check_max_length(tag, 31):
                        return False
                else:
                    return True
            else:
                return True

        return False

def check_dbedit_syntax_palo_tag(name, description, args):

    # name (str) – Name of the tag
    # color (str) – Color ID (eg. ‘color1’, ‘color4’, etc). You can use color_code() to generate the ID.
    # comments (str) – Comments

    if args.no_checks:
        return True
    else:
        if check_max_length(name, 31):
            if check_max_length(description, 255):
                return True

        return False

def check_dbedit_syntax_palo_dip(op_action, members, tag, args):

    if args.no_checks:
        return True
    else:
        if op_action == 'create' or 'delete':
            if members:
                for ip in members:
                    if not check_ip(ip):
                        return False
                else:
                    if check_max_length(tag, 31):
                        return True

        return False

def check_dbedit_syntax_palo_route(name, destination, nexthop_type, nexthop, interface, admin_dist, metric, args):

    # name (str) – The name
    # destination (str) – Destination network
    # nexthop_type (str) – ip-address or discard
    # nexthop (str) – Next hop IP address
    # interface (str) – Next hop interface
    # admin_dist (int) – Administrative distance 10-240
    # metric (int) – Metric (Default: 10) 1-65535

    if args.no_checks:
        return True
    else:
        types = ['ip-address', 'next-vr', 'discard', 'None']
        metric = int(metric)
        admin_dist = int(admin_dist)

        if check_ip(nexthop):
            if check_cidr(destination):
                if isinstance(metric, int):
                    if 1 <= metric <= 65535:
                        if check_max_length(name, 31):
                            if isinstance(admin_dist, int):
                                if 10 <= admin_dist <= 240:
                                    if nexthop_type in types:
                                        # requires the double () here to check more than one pattern
                                        if interface is None or interface.startswith(('ethernet', 'loopback')):
                                            return True

        return False

def check_dbedit_syntax_palo_application(name, category, subcategory, technology, risk, args):

    # name (str) – Name of the object
    # category ['business-systems', 'collaboration', 'general-internet', 'media', 'networking']
    # subcategory (str) – Application subcategory
    # technology (str) – Application technology
    # risk (int) – Risk of the application 1-5
    # default_type (str) – Default identification type of the application
    # default_value (list) – Values for the default type
    # parent_app (str) – Parent Application for which this app falls under
    # timeout (int) – Default timeout 0-604800
    # tcp_timeout (int) – TCP timeout 0-604800
    # udp_timeout (int) – UDP timeout 0-604800
    # tcp_half_closed_timeout (int) – TCP half closed timeout 1-604800
    # tcp_time_wait_timeout (int) – TCP wait time timeout 1-600
    # evasive_behavior (bool) – Applicaiton is actively evasive
    # consume_big_bandwidth (bool) – Application uses large bandwidth
    # used_by_malware (bool) – Application is used by malware
    # able_to_transfer_file (bool) – Application can do file transfers
    # has_known_vulnerability (bool) – Application has known vulnerabilities
    # tunnel_other_application (bool) –
    # tunnel_applications (list) – List of tunneled applications
    # prone_to_misuse (bool) –
    # pervasive_use (bool) –
    # file_type_ident (bool) –
    # virus_ident (bool) –
    # data_ident (bool) –
    # description (str) – Description of this object
    # tag (list) – Administrative tags

    if args.no_checks:
        return True
    else:
        if check_max_length(name, 31):
            if isinstance(risk, int):
                if 1 <= risk <= 5:
                    return True

        return False

def check_dbedit_syntax_palo_application_group(name, members, args):

    # name (str) – Name of the object
    # members (list) – List of service values
    # tag (list) – Administrative tags

    if args.no_checks:
        return True
    else:
        if check_max_length(name, 31):
            if members:
                return True

        return False

def check_dbedit_syntax_palo_nat_rule(name, description, tozone, args):

    # name (str) – Name of the rule
    # description (str) – The description
    # destination (list) – Destination addresses
    # destination_translated_address (str) – Translated destination IP address
    # destination_translated_port (int) – Translated destination port number 1-65535
    # disabled (bool) – Disable this rule
    # fromzone (list) – From zones
    # ha_binding (str) – Device binding configuration in HA Active-Active mode
    # nat_type (str) – Type of NAT
    # negate_target (bool) – Target all but the listed target firewalls (applies to panorama/device groups only)
    # service (str) – The service
    # source (list) – Source addresses
    # source_translation_address_type (str) – Address type for Dynamic IP And Port or Dynamic IP source translation types
    # source_translation_fallback_interface (str) – The interface for the fallback source translation
    # source_translation_fallback_ip_address (str) – The IP address of the fallback source translation
    # source_translation_fallback_ip_type (str) – The type of the IP address for the fallback source translation IP address
    # source_translation_fallback_translated_addresses (list) – Addresses for translated address types of fallback source translation
    # source_translation_fallback_type (str) – Type of fallback for Dynamic IP source translation types
    # source_translation_interface (str) – Interface of the source address translation for Dynamic IP and Port source translation types
    # source_translation_ip_address (str) – IP address of the source address translation for Dynamic IP and Port source translation types
    # source_translation_static_bi_directional (bool) – Allow reverse translation from translated address to original address
    # source_translation_static_translated_address (str) – The IP address for the static source translation
    # source_translation_translated_addresses (list) – Translated addresses of the source address translation for Dynamic IP And Port or Dynamic IP source translation types
    # source_translation_type (str) – Type of source address translation
    # tag (list) – Administrative tags
    # target (list) – Apply this policy to the listed firewalls only (applies to panorama/device groups only)
    # to_interface (str) – Egress interface from route lookup
    # tozone (list) – To zones

    if args.no_checks:
        return True
    else:
        if check_max_length(name, 31):
            if check_max_length(description, 1024):
                # can only have a single item in tozone for NAT and cannot be None
                if tozone is not None:
                    if len(tozone) == 1:
                        return True

        return False

def check_dbedit_syntax_palo_security_rule(name, action, type, description, args):

    # name (str) – Name of the rule
    # action (str) – Action to take (deny, allow, drop, reset-client, reset-server, reset-both) Note: Not all options are available on all PAN-OS versions.
    # application (list) – Applications
    # category (list) – Destination URL Categories
    # data_filtering (str) – Data Filtering Security Profile
    # description (str) – Description of this rule
    # destination (list) – Destination addresses
    # disable_server_response_inspection (bool) – Disable server response inspection
    # disabled (bool) – Disable this rule
    # file_blocking (str) – File Blocking Security Profile
    # fromzone (list) – From zones
    # group (str) – Security Profile Group
    # hip_profiles (list) – GlobalProtect host integrity profiles
    # icmp_unreachable (bool) – Send ICMP Unreachable
    # log_end (bool) – Log at session end
    # log_setting (str) – Log forwarding profile
    # log_start (bool) – Log at session start
    # negate_destination (bool) – Match on the reverse of the ‘destination’ attribute
    # negate_source (bool) – Match on the reverse of the ‘source’ attribute
    # negate_target (bool) – Target all but the listed target firewalls (applies to panorama/device groups only)
    # schedule (str) – Schedule Profile
    # service (list) – Destination services (ports) (Default: application-default)
    # source (list) – Source addresses
    # source_user (list) – Source users and groups
    # spyware (str) – Anti-Spyware Security Profile
    # tag (list) – Administrative tags
    # target (list) – Apply this policy to the listed firewalls only (applies to panorama/device groups only)
    # tozone (list) – To zones
    # type (str) – ‘universal’, ‘intrazone’, or ‘intrazone’ (Default: universal)
    # url_filtering (str) – URL Filtering Security Profile
    # virus (str) – Antivirus Security Profile
    # vulnerability (str) – Vulnerability Protection Security Profile
    # wildfire_analysis (str) – Wildfire Analysis Security Profile

    if args.no_checks:
        return True
    else:
        types = ['universal', 'interzone', 'intrazone']
        actions = ['allow', 'deny', 'drop', 'reset-client', 'reset-server', 'reset-both']

        if check_max_length(name, 31):
            if action in actions:
                if type in types:
                    if check_max_length(description, 1024):
                        return True

        return False

def get_dbedit_list(dbedit_objects, vendor, location, op_action, subclass, logger):

    # will return a list of objects per the arguments from the dbedit parsed dictionary

    action_items = list()

    for v in dbedit_objects.keys():
        if v == vendor:
            for l in dbedit_objects[v].keys():
                if l == location:
                    for a in dbedit_objects[v][l].keys():
                        if a == op_action:
                            for o in dbedit_objects[v][l][a].keys():
                                # at this point we have a list of objects for the supplied vendor, location and action
                                for i in dbedit_objects[v][l][a][o]:
                                    if issubclass(type(i), subclass):
                                        action_items.append(i)

    # need to preserve order here as rules require it!
    return list(unique_everseen(action_items))

def get_dbedit_actions(dbedit_objects, dbedit_pano_pre_rules, dbedit_pano_post_rules, vendor, location, op_action, devtype, args, logger):

    # extracts lists of pre-parsed dbedit objects per pandevice name and specific action
    addresses = list()
    address_groups = list()
    services = list()
    service_groups = list()
    tags = list()
    applications = list()
    application_groups = list()
    application_filters = list()
    pre_rules = list()
    post_rules = list()
    pre_nats = list()
    post_nats = list()
    static_routes = list()
    dips = list()
    deletions = list()
    edits = list()
    modifications = list()

    if op_action == 'create':
        if devtype == 'VRF':
            static_routes = get_dbedit_list(dbedit_objects, vendor, location, op_action, StaticRoute, logger)
        else:
            dips = get_dbedit_list(dbedit_objects, vendor, location, op_action, Dip, logger)
            addresses = get_dbedit_list(dbedit_objects, vendor, location, op_action, AddressObject, logger)
            address_groups = get_dbedit_list(dbedit_objects, vendor, location, op_action, AddressGroup, logger)
            services = get_dbedit_list(dbedit_objects, vendor, location, op_action, ServiceObject, logger)
            service_groups = get_dbedit_list(dbedit_objects, vendor, location, op_action, ServiceGroup, logger)
            tags = get_dbedit_list(dbedit_objects, vendor, location, op_action, Tag, logger)
            applications = get_dbedit_list(dbedit_objects, vendor, location, op_action, ApplicationObject, logger)
            application_groups = get_dbedit_list(dbedit_objects, vendor, location, op_action, ApplicationGroup, logger)
            application_filters = get_dbedit_list(dbedit_objects, vendor, location, op_action, ApplicationFilter, logger)
            pre_rules = get_dbedit_list(dbedit_pano_pre_rules, vendor, location, op_action, SecurityRule, logger)
            post_rules = get_dbedit_list(dbedit_pano_post_rules, vendor, location, op_action, SecurityRule, logger)
            pre_nats = get_dbedit_list(dbedit_pano_pre_rules, vendor, location, op_action, NatRule, logger)
            post_nats = get_dbedit_list(dbedit_pano_post_rules, vendor, location, op_action, NatRule, logger)

    elif op_action == 'delete':
        dips = get_dbedit_list(dbedit_objects, vendor, location, op_action, Dip, logger)
        deletions = get_dbedit_list(dbedit_objects, vendor, location, op_action, DeleteObject, logger)

    elif op_action == 'edit':
        if devtype != 'VRF':
            edits = get_dbedit_list(dbedit_objects, vendor, location, op_action, EditObject, logger)

    elif op_action == 'addtogroup' or op_action == 'removefromgroup':
        if devtype != 'VRF':
            modifications = get_dbedit_list(dbedit_objects, vendor, location, op_action, ModifyGroup, logger)

    # extract object names into 'sets' for use in 'existence' checks - beware this will make them unique if any duplicates exist
    dbedit_addresses = {o.name for o in addresses}
    dbedit_address_groups = {o.name for o in address_groups}
    dbedit_services = {o.name for o in services}
    dbedit_service_groups = {o.name for o in service_groups}
    dbedit_tags = {o.name for o in tags}
    dbedit_applications = {o.name for o in applications}
    dbedit_application_groups = {o.name for o in application_groups}
    dbedit_pre_rules = {o.name for o in pre_rules}
    dbedit_pre_nats = {o.name for o in pre_nats}
    dbedit_post_rules = {o.name for o in post_rules}
    dbedit_post_nats = {o.name for o in post_nats}
    dbedit_application_filter_names = {o.name for o in application_filters}
    dbedit_deletions = {o.name for o in deletions}
    dbedit_edits = {o.name for o in edits}
    dbedit_modifications = {o.name for o in modifications}
    dbedit_static_routes = {o.name for o in static_routes}
    dbedit_dips = {o.name for o in dips}

    if args.verbose:
        if op_action == 'create':
            if devtype == 'VRF':
                logger.info('{} \'{}\': dbedit {} requests \'{}\' StaticRoute objects'.format(devtype, location, op_action, len(dbedit_static_routes)))
            else:
                logger.info('{} \'{}\': dbedit {} requests \'{}\' Dip objects'.format(devtype, location, op_action, len(dbedit_dips)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' AddressObject objects'.format(devtype, location, op_action, len(dbedit_addresses)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' AddressGroup objects'.format(devtype, location, op_action, len(dbedit_address_groups)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' ApplicationObject objects'.format(devtype, location, op_action, len(dbedit_applications)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' ApplicationGroup objects'.format(devtype, location, op_action, len(dbedit_application_groups)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' ApplicationFilter objects'.format(devtype, location, op_action, len(dbedit_application_filter_names)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' ServiceObject objects'.format(devtype, location, op_action, len(dbedit_services)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' ServiceGroup objects'.format(devtype, location, op_action, len(dbedit_service_groups)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' Tag objects'.format(devtype, location, op_action, len(dbedit_tags)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' PreSecurityRule objects'.format(devtype, location, op_action, len(dbedit_pre_rules)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' PreNatRule objects'.format(devtype, location, op_action, len(dbedit_pre_nats)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' PostSecurityRule objects'.format(devtype, location, op_action, len(dbedit_post_rules)))
                logger.info('{} \'{}\': dbedit {} requests \'{}\' PostNatRule objects'.format(devtype, location, op_action, len(dbedit_post_nats)))
        elif op_action == 'delete':
            logger.info('{} \'{}\': dbedit {} requests \'{}\' DeleteObject objects'.format(devtype, location, op_action, len(dbedit_deletions)))
            logger.info('{} \'{}\': dbedit {} requests \'{}\' Dip objects'.format(devtype, location, op_action, len(dbedit_dips)))

        elif op_action == 'edit':
            if devtype != 'VRF':
                logger.info('{} \'{}\': dbedit {} requests \'{}\' EditObject objects'.format(devtype, location, op_action, len(dbedit_edits)))

        elif op_action == 'addtogroup' or op_action == 'removefromgroup':
            if devtype != 'VRF':
                logger.info('{} \'{}\': dbedit {} requests \'{}\' ModifyGroup objects'.format(devtype, location, op_action, len(dbedit_modifications)))

    return addresses, address_groups, services, service_groups, tags, applications, application_groups, pre_rules, post_rules, pre_nats, post_nats, deletions, edits, modifications, static_routes, dips, dbedit_addresses, dbedit_address_groups, dbedit_services, dbedit_service_groups, dbedit_tags, dbedit_applications, dbedit_application_groups, dbedit_application_filter_names, dbedit_pre_rules, dbedit_pre_nats, dbedit_post_rules, dbedit_post_nats, dbedit_deletions, dbedit_edits, dbedit_modifications, dbedit_static_routes, dbedit_dips

####################################################################################
#
# Print/Write functions
#
####################################################################################

def print_palo_object(object, logger):

    # takes pandevice object and after determining type, prints the contents

    if issubclass(type(object), AddressGroup):
        print(object.static_value, object.dynamic_value, object.description, object.tag, sep=",")

    elif issubclass(type(object), AddressObject):
        print(object.name, object.value, object.type, object.description, object.tag, sep=",")

    elif issubclass(type(object), ApplicationContainer):
        print(object.applications, sep=",")

    elif issubclass(type(object), ApplicationFilter):
        print(object.name, \
              object.category, \
              object.subcategory, \
              object.technology, \
              object.risk, \
              object.evasive, \
              object.excessive_bandwidth_use, \
              object.prone_to_misuse, \
              object.is_saas, \
              object.transfers_files, \
              object.tunnels_other_apps, \
              object.used_by_malware, \
              object.has_known_vulnerabilities, \
              object.pervasive, \
              object.tag, \
              sep=",")

    elif issubclass(type(object), ApplicationGroup):
        print(object.name, object.value, object.tag, sep=",")

    elif issubclass(type(object), ApplicationObject):
        print(object.name, \
              object.category, \
              object.subcategory, \
              object.technology, \
              object.risk, \
              object.default_type, \
              object.default_port, \
              object.default_ip_protocol,
              object.default_icmp_type, \
              object.default_icmp_code, \
              object.parent_app, \
              object.timeout, \
              object.tcp_timeout, \
              object.udp_timeout, \
              object.tcp_half_closed_timeout, \
              object.tcp_time_wait_timeout, \
              object.evasive_behavior, \
              object.consume_big_bandwidth, \
              object.used_by_malware, \
              object.able_to_transfer_file, \
              object.has_known_vulnerability, \
              object.tunnel_other_application, \
              object.tunnel_applications, \
              object.prone_to_misuse, \
              object.pervasive_use, \
              object.file_type_ident, \
              object.virus_ident, \
              object.data_ident, \
              object.description, \
              object.tag, \
              sep=",")

    elif issubclass(type(object), ServiceGroup):
        print(object.name, object.value, object.tag, sep=",")

    elif issubclass(type(object), ServiceObject):
        print(object.name, \
              object.protocol, \
              object.source_port, \
              object.destination_port, \
              object.description, \
              object.tag, \
              sep=",")

    elif issubclass(type(object), Tag):
        print(object.name, object.color, object.comments, sep=",")

    elif issubclass(type(object), Dip):
        print(object.ip, object.tag, object.action, sep=",")

    elif issubclass(type(object), StaticRoute):
        print(object.name, object.destination, object.nexthop_type, object.nexthop, object.interface, object.admin_dist, object.metric, sep=",")
        #logger.info("StaticRoute: {},{},{},{},{},{},{}".format(object.name, object.destination, object.nexthop_type, object.nexthop, object.interface, object.admin_dist, object.metric))

    elif issubclass(type(object), SecurityRule):
        print(object.name)

    elif issubclass(type(object), NatRule):
        print(object.name)

    else:
        logger.warn("Unknown type \'{}\'".format(type(object)))

def print_palo_objects_list(name, objects, logger):

    # takes list of objects and calls print_object per each item
    if objects:
        logger.info('\'{}\' list contains \'{}\' object(s)'.format(name, len(objects)))
        for o in objects:
            print_palo_object(o, logger)
    else:
        logger.info('\'{}\' list is empty so nothing to print!'.format(name))

def write_objects_dbedit_csv(filename, name, objects, ruletype, objsource, filemode, args, logger):

    # takes filename and list of pandevice objects and after determining type, writes the contents to file per CSV format
    # or write as json? but then cannot tidy up in excel if you did it that way! - json.dump(data, outfile)
    # replace newline characters with spaces in string fields, else UNIX will barf later via 'neutralise_newlines' function

    if objects:
        file_action = filemode.lower()[:1]
        csv_fields = 100

        # set the fixed values for the numbered CSV fields - must match 'read_dbedit_csv'!
        vendor = 0
        objtype = 1
        op_action = 2
        location = 3
        name = 4
        subtype = 5
        members = 6
        ip = 7
        netmask = 8
        cidr = 9
        description = 10
        color = 11
        protocol = 12
        source_port = 13
        destination_port = 14
        nexthop = 15
        tag = 16
        value = 17
        interface = 18
        enable_user_identification = 19
        metric = 20
        mgmt_profile = 21
        zone = 22
        rule_action = 23
        application = 24
        category = 25
        data_filtering = 26
        destination = 27
        disable_server_response_inspection = 28
        disabled = 29
        file_blocking = 30
        fromzone = 31
        group = 32
        hip_profiles = 33
        icmp_unreachable = 34
        log_end = 35
        log_setting = 36
        log_start = 37
        negate_destination = 38
        negate_source = 39
        negate_target = 40
        schedule = 41
        service = 42
        source = 43
        source_user = 44
        spyware = 45
        target = 46
        tozone = 47
        url_filtering = 48
        virus = 49
        vulnerability = 50
        wildfire_analysis = 51
        destination_dynamic_translated_address = 52
        destination_dynamic_translated_distribution = 53
        destination_dynamic_translated_port = 54
        destination_translated_address = 55
        destination_translated_port = 56
        ha_binding = 57
        nat_type = 58
        source_translation_address_type = 59
        source_translation_fallback_interface = 60
        source_translation_fallback_ip_address = 61
        source_translation_fallback_ip_type = 62
        source_translation_fallback_translated_addresses = 63
        source_translation_fallback_type = 64
        source_translation_interface = 65
        source_translation_ip_address = 66
        source_translation_static_bi_directional = 67
        source_translation_static_translated_address = 68
        source_translation_translated_addresses = 69
        source_translation_type = 70
        to_interface = 71
        category = 72
        subcategory = 73
        technology = 74
        risk = 75
        evasive = 76
        excessive_bandwidth_use = 77
        prone_to_misuse = 78
        is_saas = 79
        transfers_files = 80
        tunnels_other_apps = 81
        used_by_malware = 82
        has_known_vulnerabilities = 83
        pervasive = 84
        default_type = 85
        parent_app = 86
        timeout = 87
        tcp_timeout = 88
        udp_timeout = 89
        tcp_half_closed_timeout = 90
        tcp_time_wait_timeout = 91
        tunnel_applications = 92
        file_type_ident = 93
        virus_ident = 94
        data_ident = 95
        default_port = 96
        default_ip_protocol = 97
        default_icmp_type = 98
        default_icmp_code = 99

        if args.output == 'script_decides':
            fullfilename = filename+'.csv'
        else:
            fullfilename = args.output

        if args.verbose:
            logger.info('Writing file \'{}.csv\' with {} objects'.format(filename, len(objects)))

        # '+' here means 'read' as well
        try:
            with open(fullfilename, file_action + '+', encoding='utf-8', newline='') as f:

                # have to quote all the fields
                writer = csv.writer(f, delimiter=',', doublequote=False, escapechar='"', quoting=csv.QUOTE_ALL)

                # if this is the first time the file was opened then add the header
                f.seek(0)  # ensure you're at the start of the file..
                first_char = f.read(1)  # get the first character
                if not first_char:
                    # write the header row
                    writer.writerow(
                        ['#vendor', 'objtype', 'op_action', 'location', 'name', 'subtype', 'members', 'ip', 'netmask', 'cidr', \
                         'description', 'color', 'protocol', 'source_port', 'destination_port', 'nexthop', 'tag', 'value', 'interface', \
                         'enable_user_identification', 'metric', 'mgmt_profile', 'zone', 'rule_action', 'application', \
                         'category', 'data_filtering', 'destination', 'disable_server_response_inspection', 'disabled', \
                         'file_blocking', 'fromzone', 'group', 'hip_profiles', 'icmp_unreachable', 'log_end', 'log_setting', \
                         'log_start', 'negate_destination', 'negate_source', 'negate_target', 'schedule', 'service', 'source', \
                         'source_user', 'spyware', 'target', 'tozone ', 'url_filtering', 'virus', 'vulnerability', \
                         'wildfire_analysis', 'destination_dynamic_translated_address', \
                         'destination_dynamic_translated_distribution', 'destination_dynamic_translated_port', \
                         'destination_translated_address', 'destination_translated_port', 'ha_binding', 'nat_type', \
                         'source_translation_address_type', 'source_translation_fallback_interface', \
                         'source_translation_fallback_ip_address', 'source_translation_fallback_ip_type', \
                         'source_translation_fallback_translated_addresses', 'source_translation_fallback_type', \
                         'source_translation_interface', 'source_translation_ip_address', \
                         'source_translation_static_bi_directional', 'source_translation_static_translated_address', \
                         'source_translation_translated_addresses', 'source_translation_type', 'to_interface', 'category', \
                         'subcategory', 'technology', 'risk', 'evasive', 'excessive_bandwidth_use', 'prone_to_misuse', \
                         'is_saas', 'transfers_files', 'tunnels_other_apps', 'used_by_malware', 'has_known_vulnerabilities', \
                         'pervasive', 'default_type', 'parent_app', 'timeout', 'tcp_timeout', 'udp_timeout', \
                         'tcp_half_closed_timeout', 'tcp_time_wait_timeout', 'tunnel_applications', \
                         'file_type_ident', 'virus_ident', 'data_ident', 'default_port', 'default_ip_protocol', \
                         'default_icmp_type', 'default_icmp_code', 'ignore_this_end_marker'])
                else:
                    # goto end of file
                    f.seek(2)

                for p in objects:

                    row = list()

                    if issubclass(type(p), AddressGroup):

                        if p.static_value:
                            for n in range(0, csv_fields):
                                if n == vendor:
                                    row.append('palo')
                                elif n == objtype:
                                    row.append('address-group')
                                elif n == op_action:
                                    row.append('__ACTION__')
                                elif n == location:
                                    row.append(objsource)
                                elif n == name:
                                    row.append(p.name)
                                elif n == subtype:
                                    row.append('static')
                                elif n == members:
                                    row.append(p.static_value)
                                elif n == description:
                                    row.append(p.description)
                                else:
                                    row.append('')
                        else:
                            for n in range(0, csv_fields):
                                if n == vendor:
                                    row.append('palo')
                                elif n == objtype:
                                    row.append('address-group')
                                elif n == op_action:
                                    row.append('__ACTION__')
                                elif n == location:
                                    row.append(objsource)
                                elif n == name:
                                    row.append(p.name)
                                elif n == subtype:
                                    row.append('dynamic')
                                elif n == description:
                                    row.append(p.description)
                                elif n == tag:
                                    row.append(p.tag)
                                elif n == value:
                                    row.append(p.dynamic_value)
                                else:
                                    row.append('')

                    elif issubclass(type(p), AddressObject):

                        if p.type == 'ip-netmask':
                            for n in range(0, csv_fields):
                                if n == vendor:
                                    row.append('palo')
                                elif n == objtype:
                                    row.append('address')
                                elif n == op_action:
                                    row.append('__ACTION__')
                                elif n == location:
                                    row.append(objsource)
                                elif n == name:
                                    row.append(p.name)
                                elif n == subtype:
                                    row.append(p.type)
                                elif n == description:
                                    row.append(p.description)
                                elif n == tag:
                                    row.append(p.tag)
                                elif n == cidr:
                                    row.append(p.value)
                                else:
                                    row.append('')
                        else:
                            # ip-range and fqdn subtypes use 'value' field instead
                            for n in range(0, csv_fields):
                                if n == vendor:
                                    row.append('palo')
                                elif n == objtype:
                                    row.append('address')
                                elif n == op_action:
                                    row.append('__ACTION__')
                                elif n == location:
                                    row.append(objsource)
                                elif n == name:
                                    row.append(p.name)
                                elif n == subtype:
                                    row.append(p.type)
                                elif n == description:
                                    row.append(p.description)
                                elif n == tag:
                                    row.append(p.tag)
                                elif n == value:
                                    row.append(p.value)
                                else:
                                    row.append('')

                    elif issubclass(type(p), ApplicationContainer):

                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append('application-container')
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append(objsource)
                            elif n == name:
                                row.append(p.name)
                            elif n == members:
                                row.append(p.applications)
                            else:
                                row.append('')

                    elif issubclass(type(p), ApplicationFilter):

                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append('application-filter')
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append(objsource)
                            elif n == name:
                                row.append(p.name)
                            elif n == tag:
                                row.append(p.tag)
                            elif n == category:
                                row.append(p.category)
                            elif n == subcategory:
                                row.append(p.subcategory)
                            elif n == technology:
                                row.append(p.technology)
                            elif n == risk:
                                row.append(p.risk)
                            elif n == evasive:
                                if p.evasive is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == excessive_bandwidth_use:
                                if p.excessive_bandwidth_use is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == prone_to_misuse:
                                if p.prone_to_misuse is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == is_saas:
                                if p.is_saas is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == transfers_files:
                                if p.transfers_files is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == tunnels_other_apps:
                                if p.tunnels_other_apps is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == used_by_malware:
                                if p.used_by_malware is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == has_known_vulnerabilities:
                                if p.has_known_vulnerabilities is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == pervasive:
                                if p.pervasive is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            else:
                                row.append('')

                    elif issubclass(type(p), ApplicationGroup):

                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append('application-group')
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append(objsource)
                            elif n == name:
                                row.append(p.name)
                            elif n == tag:
                                row.append(p.tag)
                            elif n == members:
                                row.append(p.value)
                            else:
                                row.append('')

                    elif issubclass(type(p), ApplicationObject):
                        #print(p.__dict__)
                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append('application')
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append(objsource)
                            elif n == name:
                                row.append(p.name)
                            elif n == description:
                                row.append(p.description)
                            elif n == tag:
                                row.append(p.tag)
                            elif n == category:
                                row.append(p.category)
                            elif n == subcategory:
                                row.append(p.subcategory)
                            elif n == technology:
                                row.append(p.technology)
                            elif n == risk:
                                row.append(p.risk)
                            elif n == default_type:
                                row.append(p.default_type)
                            elif n == default_port:
                                row.append(p.default_port)
                            elif n == default_ip_protocol:
                                row.append(p.default_ip_protocol)
                            elif n == default_icmp_type:
                                row.append(p.default_icmp_type)
                            elif n == default_icmp_code:
                                row.append(p.default_icmp_code)
                            elif n == parent_app:
                                row.append(p.parent_app)
                            elif n == timeout:
                                row.append(p.timeout)
                            elif n == tcp_timeout:
                                row.append(p.tcp_timeout)
                            elif n == udp_timeout:
                                row.append(p.udp_timeout)
                            elif n == tcp_half_closed_timeout:
                                row.append(p.tcp_half_closed_timeout)
                            elif n == tcp_time_wait_timeout:
                                row.append(p.tcp_time_wait_timeout)
                            elif n == evasive:
                                if p.evasive_behavior is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == excessive_bandwidth_use:
                                if p.consume_big_bandwidth is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == used_by_malware:
                                if p.used_by_malware is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == transfers_files:
                                if p.able_to_transfer_file is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == has_known_vulnerabilities:
                                if p.has_known_vulnerability is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == tunnels_other_apps:
                                if p.tunnel_other_application is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == tunnel_applications:
                                row.append(p.tunnel_applications)
                            elif n == prone_to_misuse:
                                if p.prone_to_misuse is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == pervasive:
                                if p.pervasive_use is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == file_type_ident:
                                if p.file_type_ident is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == virus_ident:
                                if p.virus_ident is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == data_ident:
                                if p.data_ident is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            else:
                                row.append('')

                    elif issubclass(type(p), ServiceGroup):

                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append('service-group')
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append(objsource)
                            elif n == name:
                                row.append(p.name)
                            elif n == tag:
                                row.append(p.tag)
                            elif n == members:
                                row.append(p.value)
                            else:
                                row.append('')

                    elif issubclass(type(p), ServiceObject):

                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append('service')
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append(objsource)
                            elif n == name:
                                row.append(p.name)
                            elif n == description:
                                row.append(p.description)
                            elif n == tag:
                                row.append(p.tag)
                            elif n == protocol:
                                row.append(p.protocol)
                            elif n == source_port:
                                row.append(p.source_port)
                            elif n == destination_port:
                                row.append(p.destination_port)
                            else:
                                row.append('')

                    elif issubclass(type(p), Tag):

                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append('tag')
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append(objsource)
                            elif n == name:
                                row.append(p.name)
                            elif n == description:
                                row.append(p.comments)
                            elif n == color:
                                row.append(p.color)
                            else:
                                row.append('')

                    elif issubclass(type(p), Dip):

                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append('dip')
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append('shared')
                            elif n == members:
                                row.append(p.ip)
                            elif n == tag:
                                row.append(p.tag)
                            else:
                                row.append('')

                    elif issubclass(type(p), StaticRoute):

                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append('route')
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append(objsource)
                            elif n == name:
                                row.append(p.name)
                            elif n == cidr:
                                row.append(p.destination)
                            elif n == subtype:
                                row.append(p.nexthop_type)
                            elif n == nexthop:
                                row.append(p.nexthop)
                            elif n == interface:
                                row.append(p.interface)
                            elif n == value:
                                row.append(p.admin_dist)
                            elif n == metric:
                                row.append(p.metric)
                            else:
                                row.append('')

                    elif issubclass(type(p), SecurityRule):

                        #print (p.__dict__)
                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append(ruletype)
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append(objsource)
                            elif n == name:
                                row.append(p.name)
                            elif n == rule_action:
                                row.append(p.action)
                            elif n == application:
                                row.append(p.application)
                            elif n == category:
                                row.append(p.category)
                            elif n == data_filtering:
                                row.append(p.data_filtering )
                            elif n == description:
                                p.description = neutralise_newlines(p.description, args, logger)
                                row.append(p.description)
                            elif n == destination:
                                row.append(p.destination)
                            elif n == disable_server_response_inspection:
                                row.append(p.disable_server_response_inspection)
                            elif n == disabled:
                                if p.disabled is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == file_blocking:
                                row.append(p.file_blocking)
                            elif n == fromzone:
                                row.append(p.fromzone)
                            elif n == group:
                                row.append(p.group)
                            elif n == hip_profiles:
                                row.append(p.hip_profiles)
                            elif n == icmp_unreachable:
                                if p.icmp_unreachable is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == log_end:
                                if p.log_end is False:
                                    row.append('FALSE')
                                else:
                                    row.append('TRUE')
                            elif n == log_setting:
                                row.append(p.log_setting)
                            elif n == log_start:
                                if p.log_start is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == negate_destination:
                                if p.negate_destination is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == negate_source:
                                if p.negate_source is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == negate_target:
                                if p.negate_target is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == schedule:
                                row.append(p.schedule)
                            elif n == service:
                                row.append(p.service)
                            elif n == source:
                                row.append(p.source)
                            elif n == source_user:
                                row.append(p.source_user)
                            elif n == spyware:
                                row.append(p.spyware)
                            elif n == tag:
                                row.append(p.tag)
                            elif n == target:
                                row.append(p.target)
                            elif n == tozone:
                                row.append(p.tozone)
                            elif n == subtype:
                                row.append(p.type)
                            elif n == url_filtering:
                                row.append(p.url_filtering)
                            elif n == virus:
                                row.append(p.virus)
                            elif n == vulnerability:
                                row.append(p.vulnerability)
                            elif n == wildfire_analysis:
                                row.append(p.wildfire_analysis)
                            else:
                                row.append('')

                    elif issubclass(type(p), NatRule):

                        for n in range(0, csv_fields):
                            if n == vendor:
                                row.append('palo')
                            elif n == objtype:
                                row.append(ruletype)
                            elif n == op_action:
                                row.append('__ACTION__')
                            elif n == location:
                                row.append(objsource)
                            elif n == name:
                                row.append(p.name)
                            elif n == description:
                                p.description = neutralise_newlines(p.description, args, logger)
                                row.append(p.description)
                            elif n == destination:
                                row.append(p.destination)
                            elif n == destination_dynamic_translated_address:
                                row.append(p.destination_dynamic_translated_address)
                            elif n == destination_dynamic_translated_distribution:
                                row.append(p.destination_dynamic_translated_distribution)
                            elif n == destination_dynamic_translated_port:
                                row.append(p.destination_dynamic_translated_port)
                            elif n == destination_translated_address:
                                row.append(p.destination_translated_address)
                            elif n == destination_translated_port:
                                row.append(p.destination_translated_port)
                            elif n == disabled:
                                if p.disabled is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == fromzone:
                                row.append(p.fromzone)
                            elif n == ha_binding:
                                row.append(p.ha_binding)
                            elif n == nat_type:
                                row.append(p.nat_type)
                            elif n == negate_target:
                                if p.negate_target is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == service:
                                row.append(p.service)
                            elif n == source:
                                row.append(p.source)
                            elif n == source_translation_address_type:
                                row.append(p.source_translation_address_type)
                            elif n == source_translation_fallback_interface:
                                row.append(p.source_translation_fallback_interface)
                            elif n == source_translation_fallback_ip_address:
                                row.append(p.source_translation_fallback_ip_address)
                            elif n == source_translation_fallback_ip_type:
                                row.append(p.source_translation_fallback_ip_type)
                            elif n == source_translation_fallback_translated_addresses:
                                row.append(p.source_translation_fallback_translated_addresses)
                            elif n == source_translation_fallback_type:
                                row.append(p.source_translation_fallback_type)
                            elif n == source_translation_interface:
                                row.append(p.source_translation_interface)
                            elif n == source_translation_ip_address:
                                row.append(p.source_translation_ip_address)
                            elif n == source_translation_static_bi_directional:
                                if p.source_translation_static_bi_directional is True:
                                    row.append('TRUE')
                                else:
                                    row.append('FALSE')
                            elif n == source_translation_static_translated_address:
                                row.append(p.source_translation_static_translated_address)
                            elif n == source_translation_translated_addresses:
                                row.append(p.source_translation_translated_addresses)
                            elif n == source_translation_type:
                                row.append(p.source_translation_type)
                            elif n == tag:
                                row.append(p.tag)
                            elif n == target:
                                row.append(p.target)
                            elif n == interface:
                                row.append(p.to_interface)
                            elif n == tozone:
                                row.append(p.tozone)
                            else:
                                row.append('')

                    # add a final entry to ensure that if anyone edits with Excel that all the empty fields are written.
                    row.append('end')
                    writer.writerow(row)

            f.close()

            if args.verbose:
                logger.info('Closed file \'{}.csv\''.format(filename))

        except Exception as e:
            logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))
    else:
        if not args.quiet:
            logger.info('\'{}\' list is empty so nothing to write!'.format(name))

####################################################################################
#
# Collection functions - these should all have 'try' in them as they could all fail!
#
####################################################################################

def get_palo_dg_rules(tree, args, logger):

    # takes pandevice object and refreshes Device Group Security and NAT rules before returning lists of said rules
    # note that the pandevice object already contains pre/post rulebase objects in the tree before this function is called

    # instantiate empty lists in case there are no rulebase objects present
    pre_sec_rules = list()
    pre_nat_rules = list()
    post_sec_rules = list()
    post_nat_rules = list()
    pre_found = False
    post_found = False

    for child in tree.children:

        # test for child types - no rulebases exist if emtpy on Panorama
        if args.verbose == 3:
            logger.debug('get_palo_dg_rules {}'.format(str(type(child))))

        # refresh pre-rulebase
        if issubclass(type(child), PreRulebase):

            try:
                pre_sec_rules = SecurityRule.refreshall(child)
                pre_found = True
            except Exception as e:
                logger.error('Cannot refresh SecurityRule for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

            try:
                pre_nat_rules = NatRule.refreshall(child)
                pre_found = True
            except Exception as e:
                logger.error('Cannot refresh NatRule for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

        # refresh post-rulebase
        if issubclass(type(child), PostRulebase):

            try:
                post_sec_rules = SecurityRule.refreshall(child)
                post_found = True
            except Exception as e:
                logger.error('Cannot refresh SecurityRule for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

            try:
                post_nat_rules = NatRule.refreshall(child)
                post_found = True
            except Exception as e:
                logger.error('Cannot refresh NatRule for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

    # if not found then there was no rulebase objects  - eg new DG so add them!
    if not args.test:
        if not pre_found:
            p = PreRulebase()
            tree.add(p)
            try:
                p.create()
            except Exception as e:
                logger.error('Cannot create PreRulebase for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

        if not post_found:
            p = PostRulebase()
            tree.add(p)
            try:
                p.create()
            except Exception as e:
                logger.error('Cannot create PostRulebase for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

    # this will either create empty sets or not
    pre_sec_rule_names = {o.name for o in pre_sec_rules}
    pre_nat_rule_names = {o.name for o in pre_nat_rules}
    post_sec_rule_names = {o.name for o in post_sec_rules}
    post_nat_rule_names = {o.name for o in post_nat_rules}

    if args.verbose:
        logger.info('Live Device: \'{}\': Found \'{}\' PRE Security rules'.format(tree.name, len(pre_sec_rule_names)))
        logger.info('Live Device: \'{}\': Found \'{}\' PRE NAT rules'.format(tree.name, len(pre_nat_rule_names)))
        logger.info('Live Device: \'{}\': Found \'{}\' POST Security rules'.format(tree.name, len(post_sec_rule_names)))
        logger.info('Live Device: \'{}\': Found \'{}\' POST NAT rules'.format(tree.name, len(post_nat_rule_names)))

    return pre_sec_rules, post_sec_rules, pre_nat_rules, post_nat_rules, pre_sec_rule_names.union(post_sec_rule_names), pre_nat_rule_names.union(post_nat_rule_names)

def get_palo_fw_rules(tree, args, logger):

    # takes pandevice object and refreshes Firewall security/nat rules before returning lists of rules
    # note that the pandevice object already contains rulebase object in the tree before this function is called

    # instantiate empty lists in case there is no rulebase object present
    sec_rules = list()
    nat_rules = list()

    for child in tree.children:

        # test for child types - no rulebase exists if emtpy on Firewall
        if args.verbose == 3:
            logger.debug('get_palo_fw_rules {}'.format(str(type(child))))

        # refresh rulebase
        if issubclass(type(child), Rulebase):

            try:
                sec_rules = SecurityRule.refreshall(child)
            except Exception as e:
                logger.error('Cannot refresh SecurityRule for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

            try:
                nat_rules = NatRule.refreshall(child)
            except Exception as e:
                logger.error('Cannot refresh NatRule for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

    # this will either create empty sets or not
    sec_rule_names = {o.name for o in sec_rules}
    nat_rule_names = {o.name for o in nat_rules}

    if args.verbose:
        logger.info('Live Device: \'{}\': Found \'{}\' Security rules'.format(tree.name, len(sec_rule_names)))
        logger.info('Live Device: \'{}\': Found \'{}\' NAT rules'.format(tree.name, len(nat_rule_names)))

    return sec_rules, nat_rules, sec_rule_names, nat_rule_names

def get_palo_zones(tree, args, logger):

    # takes pandevice object and refreshes Firewall network objects - zones, virtual routers
    zones = list()

    # this is a list of Zone Objects
    try:
        zones = Zone.refreshall(tree, add=True)
    except Exception as e:
        logger.error('Cannot refresh Zone for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

    zone_names = {o.name for o in zones}

    if args.verbose:
        logger.info('Live Device: \'{}\': Found \'{}\' zones'.format(tree.name, len(zone_names)))

    return zones, zone_names

def get_palo_network(tree, args, logger):

    # takes pandevice object and refreshes Firewall network objects - zones, virtual routers
    zones = list()
    virtual_routers = list()

    if issubclass(type(tree), Panorama):
        name = tree.hostname
    elif issubclass(type(tree), Firewall):
        name = tree.hostname
    else:
        name = tree.name

    try:
        # this is a list of Zone Objects
        zones = Zone.refreshall(tree, add=True)
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' zones'.format(name, len(zones)))
    except Exception as e:
        logger.error('Cannot refresh Zone for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        virtual_routers = VirtualRouter.refreshall(tree, add=True)
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' virtual routers'.format(name, len(virtual_routers)))
    except Exception as e:
        logger.error('Cannot refresh VirtualRouter for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    zone_names = {o.name for o in zones}
    virtual_router_names = {o.name for o in virtual_routers}

    return zones, virtual_routers, zone_names, virtual_router_names

def get_palo_interfaces(tree, args, logger):

    # takes pandevice object and refreshes Interfaces - must use lowest subclass!
    # create list to store sub-interfaces
    all_sub_interfaces = list()
    eth_interfaces = list()
    agg_interfaces = list()
    vpn_interfaces = list()
    loop_interfaces = list()
    vlan_interfaces = list()

    if issubclass(type(tree), Panorama):
        name = tree.hostname
    elif issubclass(type(tree), Firewall):
        name = tree.hostname
    else:
        name = tree.name

    # get lists of all the Interface Objects
    try:
        eth_interfaces = EthernetInterface.refreshall(tree, add=True)
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' ethernet interfaces'.format(name, len(eth_interfaces)))
    except Exception as e:
        logger.error('Cannot refresh EthernetInterface for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))
    try:
        agg_interfaces = AggregateInterface.refreshall(tree, add=True)
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' aggregate interfaces'.format(name, len(agg_interfaces)))
    except Exception as e:
        logger.error('Cannot refresh AggregateInterface for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))
    try:
        vpn_interfaces = TunnelInterface.refreshall(tree, add=True)
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' tunnel interfaces'.format(name, len(vpn_interfaces)))
    except Exception as e:
        logger.error('Cannot refresh TunnelInterface for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))
    try:
        loop_interfaces = LoopbackInterface.refreshall(tree, add=True)
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' loopback interfaces'.format(name, len(loop_interfaces)))
    except Exception as e:
        logger.error('Cannot refresh LoopbackInterface for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))
    try:
        vlan_interfaces = VlanInterface.refreshall(tree, add=True)
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' vlan interfaces'.format(name, len(vlan_interfaces)))
    except Exception as e:
        logger.error('Cannot refresh VlanInterface for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    # sub-interfaces sit under Aggregate or Ethernet interfaces!
    for child in tree.children:
        if issubclass(type(child), AggregateInterface):
            try:
                sub_interfaces = Layer3Subinterface.refreshall(child, add=True)
                for s in sub_interfaces:
                    all_sub_interfaces.append(s)
            except Exception as e:
                logger.error('Cannot refresh Layer3Subinterface for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

        if issubclass(type(child), EthernetInterface):
            try:
                sub_interfaces = Layer3Subinterface.refreshall(child, add=True)
                for s in sub_interfaces:
                    all_sub_interfaces.append(s)
            except Exception as e:
                logger.error('Cannot refresh Layer3Subinterface for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    if args.verbose:
        logger.info('Live Device: \'{}\': Found \'{}\' sub interfaces'.format(name, len(all_sub_interfaces)))

    # extract interface names into sets
    eth_interfaces_names = {o.name for o in eth_interfaces}
    agg_interfaces_names = {o.name for o in agg_interfaces}
    vpn_interfaces_names = {o.name for o in vpn_interfaces}
    loop_interfaces_names = {o.name for o in loop_interfaces}
    vlan_interfaces_names = {o.name for o in vlan_interfaces}
    sub_interfaces_names = {o.name for o in all_sub_interfaces}

    # combine all the interface names into a single set
    tmp_interfaces1 = eth_interfaces_names.union(sub_interfaces_names)
    tmp_interfaces2 = vpn_interfaces_names.union(loop_interfaces_names)
    tmp_interfaces3 = vlan_interfaces_names.union(agg_interfaces_names)
    tmp_interfaces4 = tmp_interfaces1.union(tmp_interfaces2)
    all_interfaces = tmp_interfaces3.union(tmp_interfaces4)

    return eth_interfaces, all_sub_interfaces, vpn_interfaces, loop_interfaces, vlan_interfaces, agg_interfaces, eth_interfaces_names, sub_interfaces_names, vpn_interfaces_names, loop_interfaces_names, vlan_interfaces_names, agg_interfaces_names, all_interfaces

def get_palo_routes(tree, args, logger):

    # takes pandevice object and returns list of StaticRoute Objects and static route names
    routes = list()

    try:
        routes = StaticRoute.refreshall(tree, add=True)
    except Exception as e:
        logger.error('Cannot refresh StaticRoute for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

    route_names = {o.name for o in routes}

    if args.verbose:
        logger.info('Live Device: \'{}\': Found \'{}\' static routes'.format(tree.name, len(route_names)))

    return routes, route_names

def get_palo_objects(tree, args, logger):

    # takes pandevice object and refreshes all object types before returning lists of objects and sets of object names

    addresses = list()
    address_groups = list()
    applications = list()
    application_groups = list()
    services = list()
    service_groups = list()
    tags = list()
    application_containers = list()
    application_filters = list()
    address_names = set()
    address_group_names  = set()
    application_names = set()
    application_group_names = set()
    application_container_names = set()
    application_filter_names = set()
    service_names = set()
    service_group_names = set()
    tag_names = set()

    if issubclass(type(tree), Panorama):
        name = tree.hostname
    elif issubclass(type(tree), Firewall):
        name = tree.hostname
    else:
        name = tree.name

    try:
        # this is a list of AddressObject Objects and a set of AddressObject names
        addresses = AddressObject.refreshall(tree, add=True)
        address_names = {o.name for o in addresses}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' AddressObject objects'.format(name, len(address_names)))
    except Exception as e:
        logger.error('Cannot refresh AddressObject for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        # this is a list of AddressGroup Objects and a set of AddressGroup names
        address_groups = AddressGroup.refreshall(tree, add=True)
        address_group_names = {o.name for o in address_groups}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' AddressGroup objects'.format(name, len(address_group_names)))
    except Exception as e:
        logger.error('Cannot refresh AddressGroup for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        # this is a list of ApplicationObject Objects and a set of ApplicationObject name
        applications = ApplicationObject.refreshall(tree, add=True)
        application_names = {o.name for o in applications}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' ApplicationObject objects'.format(name, len(application_names)))
    except Exception as e:
        logger.error('Cannot refresh ApplicationObject for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        # this is a list of ApplicationGroup Objects and a set of ApplicationGroup names
        application_groups = ApplicationGroup.refreshall(tree, add=True)
        application_group_names = {o.name for o in application_groups}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' ApplicationGroup objects'.format(name, len(application_group_names)))
    except Exception as e:
        logger.error('Cannot refresh ApplicationGroup for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        # this is a list of ServiceObject Objects and a set of ServiceObject names
        services = ServiceObject.refreshall(tree, add=True)
        service_names = {o.name for o in services}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' ServiceObject objects'.format(name, len(service_names)))
    except Exception as e:
        logger.error('Cannot refresh ServiceObject for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        # this is a list of ServiceGroup Objects and a set of ServiceGroup names
        service_groups = ServiceGroup.refreshall(tree, add=True)
        service_group_names = {o.name for o in service_groups}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' ServiceGroup objects'.format(name, len(service_group_names)))
    except Exception as e:
        logger.error('Cannot refresh ServiceGroup for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        # this is a list of Tag Objects and a set of Tag names
        tags = Tag.refreshall(tree, add=True)
        tag_names = {o.name for o in tags}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' Tag objects'.format(name, len(tag_names)))
    except Exception as e:
        logger.error('Cannot refresh Tag for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        # this is a list of ApplicationContainer Objects and a set of ApplicationContainer names
        application_containers = ApplicationContainer.refreshall(tree, add=True)
        application_container_names = {o.name for o in application_containers}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' ApplicationContainer objects'.format(name, len(application_container_names)))
    except Exception as e:
        logger.error('Cannot refresh ApplicationContainer for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        # this is a list of ApplicationFilter Objects and a set of ApplicationFilter names
        application_filters = ApplicationFilter.refreshall(tree, add=True)
        application_filter_names = {o.name for o in application_filters}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' ApplicationFilter objects'.format(name, len(application_filter_names)))
    except Exception as e:
        logger.error('Cannot refresh ApplicationFilter for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    return addresses + address_groups + applications + application_groups + services + service_groups + tags + application_containers + application_filters, \
           address_names, address_group_names, application_names, application_group_names, application_container_names, application_filter_names, service_names, service_group_names, tag_names

def get_palo_predefined_objects(tree, args, logger):

    # takes pandevice object and refreshes all Predefined object types before returning 'sets' of object names
    predefined_application_names = set()
    predefined_application_container_names  = set()
    predefined_service_names = set()
    predefined_tag_names = set()

    if issubclass(type(tree), Panorama):
        name = tree.hostname
    elif issubclass(type(tree), Firewall):
        name = tree.hostname
    else:
        name = tree.name

    # Predefined objects are a special case!

    try:
        tree.predefined.refreshall_applications()
        p_apps = tree.predefined.application_objects.values()
        predefined_application_names = {o.name for o in p_apps}
        p_containers = tree.predefined.application_container_objects.values()
        predefined_application_container_names = {o.name for o in p_containers}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' Pre-Defined ApplicationObject objects'.format(name, len(predefined_application_names)))
            logger.info('Live Device: \'{}\': Found \'{}\' Pre-Defined ApplicationContainer objects'.format(name, len(predefined_application_container_names)))
    except Exception as e:
        logger.error('Cannot refresh predefined Applications for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        tree.predefined.refreshall_services()
        p_services = tree.predefined.service_objects.values()
        predefined_service_names = {o.name for o in p_services}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' Pre-Defined ServiceObject objects'.format(name, len(predefined_service_names)))
    except Exception as e:
        logger.error('Cannot refresh predefined Services for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    try:
        tree.predefined.refreshall_tags()
        p_tags = tree.predefined.tag_objects.values()
        predefined_tag_names = {o.name for o in p_tags}
        if args.verbose:
            logger.info('Live Device: \'{}\': Found \'{}\' Pre-Defined Tag objects'.format(name, len(predefined_tag_names)))
    except Exception as e:
        logger.error('Cannot refresh predefined Tags for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    return predefined_application_names, predefined_application_container_names, predefined_service_names, predefined_tag_names

def get_palo_dips(tree, args, logger):

    # takes pandevice object and returns list of registered-ip Objects
    # tree.userid.unregister(ip, tags)
    # if >500 objects pan-os returns file to download instead.
    # run 'show object registered-ip all option file', which will write the file to /var/log/pan/regipdump instead. Then you can view the file with 'less mp-log regipdump'.

    dips = list()

    if issubclass(type(tree), Firewall):
        name = tree.hostname
    else:
        name = tree.name

    try:
        dips_dict = tree.userid.get_registered_ip()

        for ip in dips_dict.keys():
            for tag in dips_dict[ip]:
                o = Dip(ip=ip, tag=tag)
                dips.append(o)

    except Exception as e:
        logger.error("{}".format(neutralise_newlines(repr(e), args, logger)))

    dip_names = {o.name for o in dips}

    if args.verbose:
        logger.info('Live Device: \'{}\': Found \'{}\' registered-IPs (DIPs)'.format(name, len(dip_names)))

    return dips, dip_names

def get_palo_device_group_zones(tree, args, logger):

    # takes pandevice object and returns list of zones

    # this is very annoying, basically we need to collect zones but these are in the Template.
    # this is further compounded by the use of Template Stacks! so that part is not support as yet
    # there is no direct mapping between Template and Device Group so need to pull associated firewall serial numbers from all and compare

    templates = list()
    device_groups = list()
    template_zones = defaultdict(list)
    template_devices = defaultdict(list)
    dg_devices = defaultdict(list)
    dg_zones = defaultdict(list)
    gp_zones = defaultdict(set)

    try:
        templates = Template.refreshall(tree)
        # template_stacks = TemplateStack.refreshall(tree)
    except Exception as e:
        logger.error('Cannot refresh Templates for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))


    # determine devices attached to Templates and Zones available to Templates for attached devices only
    for template in templates:
        if template.devices:
            for device in template.devices:
                template_devices[template.name].append(device)

            # zones for the Templates are children of Vsys
            for child in template.children:
                if issubclass(type(child), Vsys):
                    zones, live_zone_names = get_palo_zones(child, args, logger)
                    if live_zone_names:
                        for z in live_zone_names:
                            template_zones[template.name].append(z)

    # determine devices attached to Device Groups
    try:
        device_groups = DeviceGroup.refreshall(tree)
    except Exception as e:
        logger.error('Cannot refresh DeviceGroup for device \'{}\', ({}).'.format(tree.name, neutralise_newlines(repr(e), args, logger)))

    for dg in device_groups:
        for child in dg.children:
            if issubclass(type(child), Firewall):
                try:
                    child.refresh_system_info()
                    if child.serial:
                        dg_devices[dg.name].append(child.serial)
                except Exception as e:
                    logger.error('Cannot refresh_system_info for device \'{}\', ({}).'.format(child.name, neutralise_newlines(repr(e), args, logger)))

    # find matches on serial number to create dictionary of available zones
    for dg in dg_devices:
        for sn in dg_devices[dg]:
            for td in template_devices:
                for s in template_devices[td]:
                    if s == sn:
                        for t in template_zones:
                            if t == td:
                                for z in template_zones[t]:
                                    dg_zones[dg].append(z)

    # make the zones unique
    for gp in dg_zones:
        gp_zones[gp] = set(dg_zones[gp])

    return gp_zones

def get_palo_device_group_network_info(tree, args, logger):

    # takes pandevice object and returns list of zones and interfaces

    # this is very annoying, basically we need to collect zones/interfaces but these are in the Template.
    # this is further compounded by the use of Template Stacks! so that part is not support as yet
    # there is no direct mapping between Template and Device Group so need to pull associated firewall serial numbers from all and compare
    # this also requires firewalls are online and connected to Panorama!

    templates = list()
    device_groups = list()
    template_zones = defaultdict(list)
    template_devices = defaultdict(list)
    template_interfaces = defaultdict(list)
    dg_devices = defaultdict(list)
    dg_zones = defaultdict(list)
    dg_interfaces = defaultdict(list)
    gp_zones = defaultdict(set)
    gp_interfaces = defaultdict(set)

    try:
        templates = Template.refreshall(tree)
        # template_stacks = TemplateStack.refreshall(tree)
    except Exception as e:
        logger.error('Cannot refresh Templates for device \'{}\', ({}).'.format(tree.hostname, neutralise_newlines(repr(e), args, logger)))

    # determine Zones and Interfaces for attached devices only (e.g. Templates with devices)
    for template in templates:
        if template.devices:
            for device in template.devices:
                # record the serial number under this template
                template_devices[template.name].append(device)

            # zones for the Templates are children of Vsys
            for child in template.children:
                if issubclass(type(child), Vsys):
                    zones, live_zone_names = get_palo_zones(child, args, logger)
                    if live_zone_names:
                        for z in live_zone_names:
                            # record the zone name in under this template
                            template_zones[template.name].append(z)

            # interfaces are in the Template
            phy_interfaces, sub_interfaces, vpn_interfaces, loop_interfaces, vlan_interfaces, agg_interfaces, live_phy_interfaces_names, live_sub_interfaces_names, live_vpn_interfaces_names, live_loop_interfaces_names, live_vlan_interfaces_names, live_agg_interfaces_names, all_interfaces = get_palo_interfaces(template, args, logger)

            if all_interfaces:
                for i in all_interfaces:
                    # record the interface name under this template
                    template_interfaces[template.name].append(i)

    # determine devices attached to Device Groups
    try:
        device_groups = DeviceGroup.refreshall(tree)
    except Exception as e:
        logger.error('Cannot refresh DeviceGroup for device \'{}\', ({}).'.format(tree.hostname, neutralise_newlines(repr(e), args, logger)))

    for dg in device_groups:
        for child in dg.children:
            if issubclass(type(child), Firewall):
                # this is the part that needs firewall to be connected
                try:
                    child.refresh_system_info()
                    if child.serial:
                        # record the serial number under this Device Group
                        dg_devices[dg.name].append(child.serial)
                except Exception as e:
                    logger.error('Cannot refresh_system_info for device \'{}\', ({}).'.format(child.hostname, neutralise_newlines(repr(e), args, logger)))
                    pass

    # find matches on serial number to create dictionary of available network information
    for dg in dg_devices:
        for sn in dg_devices[dg]:
            for td in template_devices:
                for s in template_devices[td]:
                    if s == sn:
                        # we have a match on serial numbers here so Template must pair with Device Group
                        for t in template_zones:
                            if t == td:
                                for z in template_zones[t]:
                                    dg_zones[dg].append(z)

                        for t in template_interfaces:
                            if t == td:
                                for z in template_interfaces[t]:
                                    dg_interfaces[dg].append(z)

    # make the zones unique
    for gp in dg_zones:
        gp_zones[gp] = set(dg_zones[gp])

    for gp in dg_interfaces:
        gp_interfaces[gp] = set(dg_interfaces[gp])

    return gp_zones, gp_interfaces

####################################################################################
#
# Utility functions
#
####################################################################################

def decomment(csvfile, args, logger):

    # takes a csv file and will ignore lines beginning with '#' and 'empty' lines and return generator
    # https://stackoverflow.com/questions/231767/what-does-the-yield-keyword-do

    for row in csvfile:
        if row.startswith('#'):
            if args.verbose:
                logger.info("dbedit: Ignoring commented line \'{}\'".format(row.rstrip()))
        elif row.isspace():
            if args.verbose:
                logger.info("dbedit: Ignoring empty line \'{}\'".format(row.rstrip()))
        else:
            yield row

def get_args():

    # Note: for '--no-checks' - args replaces middle hyphen with underscore so validation in main script is 'args.no_checks'!

    # Get optional arguments store_true = boolean
    parser = argparse.ArgumentParser(description="Connect to the API of a Palo Alto Device")

    # Device login related arguments
    fw_group = parser.add_argument_group('Security Device Login')
    fw_group.add_argument('-d', '--device', action='store', required=True, help="Hostname of device")
    fw_group.add_argument('-u', '--username', action='store', required=True, help="Username of device")
    fw_group.add_argument('-p', '--password', action='store', required=True, help="Password of device")
    fw_group.add_argument('-l', '--location', action='store', required=False, help="Device Group, VSYS or VRF")

    # Display/Output options
    log_group = parser.add_argument_group('Display/Output')
    log_group.add_argument('-o', '--output', nargs='?', const='script_decides', default=False, help="Write CSV. Provide optional output filename or let script decide")
    log_group1 = log_group.add_mutually_exclusive_group(required=False)
    log_group1.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbosity)")
    log_group1.add_argument('-q', '--quiet', action='store_true', help="No informational console output")

    # API action options
    api_group = parser.add_argument_group('CSV file actions')
    api_group.add_argument('-f', '--filename', action='store', required=False, help="CSV input file")
    api_group.add_argument('--no-checks', action='store_true', help="Do not perform object integrity checks")
    api_group.add_argument('--no-locks', action='store_true', help="Do not take config/commit locks (use for DIP updates)")

    api_group1 = api_group.add_mutually_exclusive_group(required=False)
    api_group1.add_argument('-t', '--test', action='store_true', help="Test config from CSV input file")
    api_group1.add_argument('-c', '--commit', action='store_true', help="Commit changes")

    api_group2 = api_group.add_mutually_exclusive_group(required=False)
    api_group2.add_argument('-i', '--interactive', action='store_true', help="Prompt for user confirmation")
    api_group2.add_argument('-a', '--auto', action='store_true', help="Automation Mode")

    return parser.parse_args()

def get_palo_filename(tree, args, logger):

    # takes pandevice object and returns name suitable for filename and other uses

    if issubclass(type(tree), Panorama):
        name = tree.hostname
    elif issubclass(type(tree), Firewall):
        name = tree.hostname
    else:
        name = tree.name

    filename = "generic"

    try:
        me = tree.about()

        if 'name' in me.keys():
            filename = str(me['name'])
        elif 'hostname' in me.keys():
            filename = ''.join(str(me['hostname']).split(".", 0))  # return up to first full stop
        elif 'display_name' in me.keys():
            filename = str(me['display_name'])  # return vsys display name
        else:
            try:
                ss = SystemSettings.refreshall(tree)
                for s in ss:
                    if s.hostname:
                        filename = str(s.hostname) # return fw hostname
            except Exception as e:
                logger.error('Cannot refresh SystemSettings for device \'{}\', ({}) exiting...'.format(name, neutralise_newlines(repr(e), args, logger)))
    except Exception as e:
        logger.error('Cannot query about for device \'{}\', ({}).'.format(name, neutralise_newlines(repr(e), args, logger)))

    return filename

def make_list_from_str(s):

    # takes a string in the format ['item1', 'item2', 'item3', 'item 4 has space'] and will return a list of these items

    empty_list = list()

    if ', ' in s:
        s = s.replace(", ", ",")

    if '[' in s:
        s = s.replace("[", "")

    if ']' in s:
        s = s.replace("]", "")

    if '\'' in s:
        s = s.replace("'", "")

    if ',' in s:
        # split returns a list
        return s.split(',')
    else:
        if s == '':
            return None
        else:
            # if we cant split we can return our own list
            return [s]

def check_ip(i):

    # will return boolean value depending on IP provided

    try:
        ip = ipaddress.ip_address(i)
    except ValueError as e:
        return False
    else:
        return True

def check_cidr(i):

    # will return boolean value depending on CIDR provided

    try:
        ip = ipaddress.ip_network(i)
    except ValueError as e:
        return False
    else:
        return True

def check_max_length(n, length):

    # will return boolean value depending on string and length provided

    if 1 <= len(n) <= int(length):
        return True
    else:
        return False

def commit_palo(tree, args, logger):

    # Perform a commit if requested

    if args.commit:
        if not args.quiet:
            logger.info('Committing configuration for device \'{}\'.'.format(tree.hostname))
        try:
            tree.commit(sync=True)
        except Exception as e:
            logger.error('Cannot commit for device \'{}\', ({}).'.format(args.device, neutralise_newlines(repr(e), args, logger)))
            return False

    return True

def set_logging(logfile):

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create a file handler and set level to info
    fh = logging.FileHandler(logfile)
    fh.setLevel(logging.INFO)

    # create a logging format and add to handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger

def neutralise_newlines(value, args, logger):

    # check for newlines in strings and replace with space, else UNIX will barf later

    if value:
        if isinstance(value, str):
            if '\n' in value:
                if args.verbose == 2:
                    logger.info('String contains control characters: \'{}\''.format(repr(value)))  # print control characters
                value = value.replace('\n', ' ')

    return value

def send_email(subject, toaddress, filename, message, args, logger):

    # dont send emails unless test is on

    if not args.test:
        mailserver = __mail_server__
        fromaddress = __from_address__

        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = fromaddress
        msg['To'] = toaddress
        msg.attach(MIMEText(message, 'plain'))

        attachment = open(filename, "rb")
        part = MIMEBase('application', 'octet-stream')
        part.set_payload((attachment).read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', "attachment; filename= %s" % filename)

        msg.attach(part)

        text = msg.as_string()
        try:
            server = smtplib.SMTP(mailserver)
            server.sendmail(fromaddress, toaddress, text)
            server.quit()
            logger.info('Successfully sent email to : \'{}\''.format(toaddress))
        except Exception as e:
            logger.error('Cannot send email to : \'{}\' - {}'.format(toaddress, neutralise_newlines(repr(e), args, logger)))
    else:
        if not args.quiet:
            logger.info('Not sending email as update not requested.')

def wipe_candidate_config(tree, args, logger):

    # takes pandevice object and reverts to running configuration

    try:
        tree.revert_to_running_configuration()
        if not args.quiet:
            logger.info('Live Device: \'{}\': Candidate Configuration Cleared.'.format(tree.hostname))
        release_locks(tree, args, logger)
    except Exception as e:
        logger.error('Cannot Revert to Running Configuration \'{}\', ({}) exiting...'.format(args.device, neutralise_newlines(repr(e), args, logger)))

def take_locks(tree, args, logger):

    # takes pandevice object and takes locks

    # take commit lock for the device
    try:
        tree.add_commit_lock()
        if args.verbose:
            logger.info('Live Device: \'{}\': Commit lock obtained'.format(tree.hostname))
    except Exception as e:
        logger.error('Cannot take commit lock for device \'{}\', ({}) exiting...'.format(args.device, neutralise_newlines(repr(e), args, logger)))
        sys.exit(1)

    # take config lock for the device
    try:
        tree.add_config_lock()
        if args.verbose:
            logger.info('Live Device: \'{}\': Config lock obtained'.format(tree.hostname))
    except Exception as e:
        logger.error('Cannot take config lock for device \'{}\', ({}) exiting...'.format(args.device, neutralise_newlines(repr(e), args, logger)))
        sys.exit(1)

def release_locks(tree, args, logger):

    # takes pandevice object and releases locks - we don't want to leave these unintentionally locked so try ten times

    # release config locks for the device
    commit_released = False
    config_released = False
    max_attempts = 10

    for attempt in range (1, max_attempts):
        if not args.quiet:
            logger.info('Live Device: \'{}\': Commit lock relinquish attempt {} of {}'.format(tree.hostname, attempt, max_attempts))
        try:
            tree.remove_commit_lock()
            if args.verbose:
                logger.info('Live Device: \'{}\': Commit lock released'.format(tree.hostname))
            commit_released = True
            break
        except Exception as e:
            logger.error('Cannot release commit lock for device \'{}\', ({}).'.format(args.device, neutralise_newlines(repr(e), args, logger)))

    for attempt in range (1, 10):
        if not args.quiet:
            logger.info('Live Device: \'{}\': Config lock relinquish attempt {} of {}'.format(tree.hostname, attempt, max_attempts))
        try:
            tree.remove_config_lock()
            if args.verbose:
                logger.info('Live Device: \'{}\': Config lock released'.format(tree.hostname))
            config_released = True
            break
        except Exception as e:
            logger.error('Cannot release config lock for device \'{}\', ({}).'.format(args.device, neutralise_newlines(repr(e), args, logger)))

    if not commit_released:
        logger.error('Failed to release Commit Lock for device \'{}\', after \'{}\' attempts. Manually log in an run \'request commit-lock remove\''.format(args.device, '10'))
        sys.exit(1)

    if not config_released:
        logger.error('Failed to release Config Lock for device \'{}\', after \'{}\' attempts. Manually log in an run \'request config-lock remove\''.format(args.device, '10'))
        sys.exit(1)

def tidy_up(tree, failures, args, logger):

    if args.filename and not args.test:
        if failures:
            if args.commit:
                logger.error('API update failures exist. Not committing configuration! Reverting... \'{}\''.format(tree.hostname))
                wipe_candidate_config(tree, args, logger)
            else:
                if not args.no_locks:
                    logger.error('API update failures exist. Not releasing locks. Please investigate! \'{}\''.format(tree.hostname))
                else:
                    logger.error('API update failures exist. Please investigate! \'{}\''.format(tree.hostname))
        else:
            if args.commit:
                if commit_palo(tree, args, logger):
                    if not args.no_locks:
                        release_locks(tree, args, logger)
                else:
                    if not args.no_locks:
                        logger.error('Commit failure occurred. Not releasing locks. Please investigate! \'{}\''.format(tree.hostname))

def main():

    ###############################################################################
    #
    # set up Logging and emails
    #
    ###############################################################################

    t = today.strftime('%Y-%m-%d-%H-%M-%S')
    logfile = 'Firewall_API_Output-' + t + '.log'
    logger = set_logging(logfile)
    emails = list()
    sudouser = os.environ.get('SUDO_USER')
    if sudouser and (sudouser != 'root' and sudouser != 'None' and sudouser not in emails):
        emails.append(sudouser) 

    email_message = str()
    email_subject = 'Palo Automation - firewall_api_multi_tool - ' + t

    ###############################################################################
    #
    # Get CLI arguments and re-iterate now instead of later in the script
    #
    ###############################################################################

    args = get_args()

    if args.device:
       logger.info("Argument \'--device\' supplied, device in scope \'{}\'".format(args.device))
    if args.location:
       logger.info("Argument \'--location\' supplied, location in scope \'{}\' only.".format(args.location))
    if args.filename:
       logger.info("Argument \'--filename\' supplied, configuration contained in \'{}\'".format(args.filename))
    if args.no_checks:
       logger.info('Argument \'--no-checks\' supplied, no integrity checks performed on dbedit file or in relation to existing configuration.')
    if args.no_locks:
       logger.info('Argument \'--no-locks\' supplied, no commit or configuration locks will be taken.')
    if args.test:
       logger.info('Argument \'--test\' supplied, TEST mode - will not perform updates via API.')
    if args.commit:
       logger.info('Argument \'--commit\' supplied, COMMIT mode - commit on device will occur (if no API failures occur).')
    if args.interactive:
       logger.info('Argument \'--interactive\' supplied, confirmation questions requested.')
    if args.interactive:
       logger.info('Argument \'--auto\' supplied, automation mode (sends emails).')
    if args.output:
       if args.output == 'script_decides':
           logger.info('Argument \'--output\' supplied, configuration output file will be created. Filename determined by script.')
       else:
           logger.info('Argument \'--output\' supplied, configuration output file will be created. Filename \'{}\'.'.format(args.output))
    if args.verbose == 1:
       logger.info('Argument \'--verbose\' supplied, logging will be printed to console.')
    if args.verbose == 2:
       logger.info('Argument \'--vv\' supplied, additional logging will be printed to console.')
    if args.verbose == 3:
       logger.info('Argument \'--vvv\' supplied, debug logging will be printed to console.')
    if args.quiet:
       logger.info('Argument \'--quiet\' supplied, no informational output.')

    time.sleep(1)  # Delay for 1 second

    # interactive mode, add in ability here to provide email address?
    if args.interactive:
        while True:
            response = input("Confirm these details and continue? <yes/no> ")
            while response.lower() not in ("yes", "no", "y", "n"):
                response = input("Continue? <yes/no> ")
            if response == "yes" or response == "y":
                break
            else:
                sys.exit(0)
    elif args.auto:
        # should mean we are not used in automation
        emails.append(__api_notification_email__)

    ###############################################################################
    #
    # Connect to the PAN-OS device and determine its type (Firewall or Panorama).
    #
    ###############################################################################

    try:
        device = PanDevice.create_from_device(args.device, args.username, args.password)
    except Exception as e:
        logger.error('Cannot open API to device \'{}\', ({}) exiting...'.format(args.device, neutralise_newlines(repr(e), args, logger)))
        for email in emails:
            send_email(email_subject, email + __email_domain__, logfile, email_message, args, logger)
        sys.exit(1)

    ###############################################################################
    #
    # check various statuses - much of this is unreliable data
    #
    ###############################################################################

    try:
        logger.info('Device System Info: {0}'.format(device.refresh_system_info()))
    except Exception as e:
        logger.error('Cannot refresh_system_info for device \'{}\', ({}).'.format(args.device, neutralise_newlines(repr(e), args, logger)))

    ###############################################################################
    #
    # if a filename was supplied then parse that into 'dbedit_objects' dictionary
    #
    ###############################################################################

    failures = set()
    null_set = set()
    dbedit_objects = dict()

    # order of this list is important - DO NOT EDIT!
    csv_action_types = ['delete', 'create', 'edit', 'addtogroup', 'removefromgroup']

    if args.filename:
        if not args.quiet:
            logger.info('Filename \'{}\' provided. Parsing...'.format(args.filename))
        dbedit_objects, dbedit_pano_pre_rules, dbedit_pano_post_rules = read_dbedit_csv(args, logger, args.filename, emails, email_subject, email_message, logfile)

    ###############################################################################
    #
    # Panorama section
    #
    ###############################################################################

    if issubclass(type(device), Panorama):

        if not args.quiet:
            logger.info('Connecting to Panorama \'{}\''.format(args.device))

        try:
            pano = Panorama(args.device, args.username, args.password)
        except Exception as e:
            logger.error('Cannot open API to device \'{}\', ({}) exiting...'.format(args.device, neutralise_newlines(repr(e), args, logger)))
            for email in emails:
                send_email(email_subject, email + __email_domain__, logfile, email_message, args, logger)
            sys.exit(1)

        ###############################################################################
        #
        # Take Configuration/Commit Locks
        #
        ###############################################################################

        if args.filename and not args.test and not args.no_locks:
            take_locks(pano, args, logger)

        if args.location:

            ###############################################################################
            #
            # Collect Global and Predefined objects, Zones and Interfaces if required (e.g. only if we need them later)
            #
            ###############################################################################

            if args.output or (args.filename and not args.no_checks):

                # collect Global Objects
                if args.verbose:
                    logger.info('Collecting Global Objects from Panorama \'{}\''.format(pano.hostname))

                all_global_objects, G_address_names, G_address_group_names, G_application_names, G_application_group_names, G_application_container_names, G_application_filter_names, G_service_names, G_service_group_names, G_tag_names = get_palo_objects(pano, args, logger)

                # collect Pre-Defined Objects
                if args.verbose:
                    logger.info('Collecting Predefined Objects from \'{}\''.format(pano.hostname))

                pd_live_application_names, pd_live_application_container_names, pd_live_service_names, pd_live_tag_names = get_palo_predefined_objects(pano, args, logger)

                # Collect Zone and Interface details
                if args.verbose:
                    logger.info('Collecting Zone and Interface Objects from \'{}\''.format(pano.hostname))

                device_group_zones, device_group_interfaces = get_palo_device_group_network_info(pano, args, logger)

            ###############################################################################
            #
            # figure out which Device Groups are in scope (supports ALL or specific)
            #
            ###############################################################################

            try:
                device_groups = DeviceGroup.refreshall(pano)

                if args.verbose:
                    for device_group in device_groups:
                        logger.info('Live Device: Found Device Group \'{}\''.format(device_group.name))

                if args.location == 'ALL':
                    if not args.quiet:
                        logger.info('ALL Device Groups requested for scope')
                else:
                    for device_group in device_groups:
                        if device_group.name == args.location:
                            if not args.quiet:
                                logger.info('Matched Device Group \'{}\' with supplied argument'.format(args.location))
                            break
                    else:
                        logger.error('Requested Device Group \'{}\' is not found, exiting...'.format(args.location))
                        for email in emails:
                            send_email(email_subject, email + __email_domain__, logfile, email_message, args, logger)
                        if args.filename and not args.test and not args.no_locks:
                            release_locks(pano, args, logger)
                        sys.exit(1)

                    for device_group in device_groups:
                        if device_group.name != args.location:
                            if args.verbose == 2:
                                logger.info('Removing Device Group \'{}\' from tree'.format(device_group.name))
                            pano.remove(device_group)

            except Exception as e:
                logger.error('Cannot refresh DeviceGroup for device \'{}\', ({}) exiting...'.format(pano.hostname, neutralise_newlines(repr(e), args, logger)))
                if args.filename and not args.test and not args.no_locks:
                    release_locks(pano, args, logger)
                sys.exit(1)

            ###############################################################################
            #
            # iterate over the Device Groups added to 'pano'
            #
            ###############################################################################

            for child in pano.children:

                if args.verbose == 3:
                    logger.debug('Panorama Child {}'.format(str(type(child))))

                if issubclass(type(child), DeviceGroup):
                    filename = get_palo_filename(child, args, logger)

                    ###############################################################################
                    #
                    # get 'lists' and 'sets' of Device Group Objects, Rules, Zones and Interfaces
                    #
                    ###############################################################################

                    if args.output or (args.filename and not args.no_checks):

                        # collect Device Group Objects
                        if args.verbose:
                            logger.info('Collecting objects for Device Group \'{}\''.format(child.name))

                        all_dg_objects, dg_address_names, dg_address_group_names, dg_application_names, dg_application_group_names, dg_application_container_names, dg_application_filter_names, dg_service_names, dg_service_group_names, dg_tag_names = get_palo_objects(child, args, logger)

                        # collect Device Group Rules
                        if args.verbose:
                            logger.info('Collecting rules for Device Group \'{}\''.format(child.name))

                        pre_sec_rules, post_sec_rules, pre_nat_rules, post_nat_rules, dg_rule_names, dg_nat_names = get_palo_dg_rules(child, args, logger)

                        # collect Device Group zones and interfaces (requires connected firewalls)
                        if args.filename and not args.no_checks:
                            dg_zone_names = device_group_zones[child.name]
                            dg_interface_names = device_group_interfaces[child.name]

                            # collect Device Group objects from dbedit file
                            a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, dbedit_addresses, dbedit_address_groups, dbedit_services, dbedit_service_groups, dbedit_tags, dbedit_applications, dbedit_application_groups, dbedit_application_filter_names, dbedit_pre_rules, dbedit_pre_nats, dbedit_post_rules, dbedit_post_nats, dbedit_deletions, dbedit_edits, dbedit_modifications, dbedit_static_routes, dbedit_dips = get_dbedit_actions(dbedit_objects, dbedit_pano_pre_rules, dbedit_pano_post_rules, 'palo', child.name, 'create', 'Device Group', args, logger)

                    ###############################################################################
                    #
                    # write objects/rules output files as requested
                    #
                    ###############################################################################

                    if args.output:
                        write_objects_dbedit_csv(filename + '_apidata-' + t, 'Device Group Objects', all_dg_objects, None, child.name, 'append', args, logger)
                        write_objects_dbedit_csv(filename + '_apidata-' + t, 'Device Group Pre-Security Rules', pre_sec_rules, 'pre-security-rule', child.name, 'append', args, logger)
                        write_objects_dbedit_csv(filename + '_apidata-' + t, 'Device Group Post-Security Rules', post_sec_rules, 'post-security-rule', child.name, 'append', args, logger)
                        write_objects_dbedit_csv(filename + '_apidata-' + t, 'Device Group Pre-NAT Rules', pre_nat_rules, 'pre-nat-rule', child.name, 'append', args, logger)
                        write_objects_dbedit_csv(filename + '_apidata-' + t, 'Device Group Post-NAT Rules', post_nat_rules, 'post-nat-rule', child.name, 'append', args, logger)

                    ###############################################################################
                    #
                    # print objects/rules to console as requested
                    #
                    ###############################################################################

                    if args.verbose == 2:
                        print_palo_objects_list(child.name + ' All Objects', all_dg_objects, logger)
                        print_palo_objects_list(child.name + ' Pre-Security Rules', pre_sec_rules, logger)
                        print_palo_objects_list(child.name + ' Post-Security Rules', post_sec_rules, logger)
                        print_palo_objects_list(child.name + ' Pre-Security Rules', pre_nat_rules, logger)
                        print_palo_objects_list(child.name + ' Post-NAT Rules', post_nat_rules, logger)

                    ###############################################################################
                    #
                    # Assess updates to Device Group from dbedit
                    #
                    ###############################################################################

                    if args.filename:

                        if not args.quiet:
                            logger.info('Device Group \'{}\': dbedit update checking...'.format(child.name))

                        ###############################################################################
                        #
                        # Combine all the various object names Global, Device Group, DBedit into sets
                        #
                        ###############################################################################

                        if not args.no_checks:

                            global_tag_names = pd_live_tag_names.union(G_tag_names)
                            global_application_names = pd_live_application_names.union(G_application_names)
                            global_application_container_names = pd_live_application_container_names.union(G_application_container_names)
                            global_service_names = pd_live_service_names.union(G_service_names)

                            available_address_names = dg_address_names.union(G_address_names)
                            available_address_group_names = dg_address_group_names.union(G_address_group_names)
                            staged_application_names = dg_application_names.union(global_application_names)
                            available_application_group_names = dg_application_group_names.union(G_application_group_names)
                            available_application_filter_names = dg_application_filter_names.union(G_application_filter_names)
                            available_service_names = dg_service_names.union(global_service_names)
                            available_service_group_names = dg_service_group_names.union(G_service_group_names)
                            available_tag_names = dg_tag_names.union(global_tag_names)
                            available_application_names = staged_application_names.union(global_application_container_names)

                            dg_route_names = set()

                        else:

                            # just make empty sets instead
                            available_address_names = set()
                            available_address_group_names = set()
                            available_application_names = set()
                            available_application_group_names = set()
                            available_application_filter_names = set()
                            available_service_names = set()
                            available_service_group_names = set()
                            available_tag_names = set()

                            dg_zone_names = set()
                            dg_rule_names = set()
                            dg_nat_names = set()
                            dg_interface_names = set()
                            dg_route_names = set()

                        ###############################################################################
                        #
                        # dbedit file was already parsed - extract dbedit instructions per action type specific to this Device Group
                        #
                        ###############################################################################

                        for action in csv_action_types:

                            addresses, address_groups, services, service_groups, tags, applications, application_groups, pre_rules, post_rules, pre_nats, post_nats, deletions, edits, modifications, static_routes, dips, dbedit_addresses, dbedit_address_groups, dbedit_services, dbedit_service_groups, dbedit_tags, dbedit_applications, dbedit_application_groups, dbedit_application_filter_names, dbedit_pre_rules, dbedit_pre_nats, dbedit_post_rules, dbedit_post_nats, dbedit_deletions, dbedit_edits, dbedit_modifications, dbedit_static_routes, dbedit_dips = get_dbedit_actions(dbedit_objects, dbedit_pano_pre_rules, dbedit_pano_post_rules, 'palo', child.name, action, 'Device Group', args, logger)

                            ###############################################################################
                            #
                            # Create all the objects and rules ensuring specific creation order - DO NOT 'union' with dbedit for the object being created!
                            #
                            ###############################################################################

                            # update Tags
                            update_objects(tags, child, 'Device Group', child.name, action, args, logger, filename, failures, available_tag_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Addresses
                            update_objects(addresses, child, 'Device Group', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Address Groups
                            update_objects(address_groups, child, 'Device Group', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Services
                            update_objects(services, child, 'Device Group', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), null_set, null_set, available_service_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Service Groups
                            update_objects(service_groups, child, 'Device Group', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), null_set, null_set, available_service_names.union(dbedit_services), available_service_group_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Applications
                            update_objects(applications, child, 'Device Group', child.name, action, args, logger, filename, failures, null_set, null_set, null_set, null_set, null_set, available_application_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Application Groups
                            update_objects(application_groups, child, 'Device Group', child.name, action, args, logger, filename, failures, null_set, null_set, null_set, null_set, null_set, available_application_names.union(dbedit_applications), available_application_group_names, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Security and NAT rules - don't forget the hierarchy here, Device Group->Pre/Post-Rulebase->SecurityRule/NatRule
                            for grandchild in child.children:

                                if args.verbose == 3:
                                    logger.debug('Device Group Child {}'.format(str(type(grandchild))))

                                if issubclass(type(grandchild), PreRulebase):
                                    # update Rules by sending PreRulebase object (e.g. grandchild)
                                    update_objects(pre_rules, grandchild, 'Device Group', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), dg_rule_names, dg_zone_names, dg_nat_names, dg_interface_names, null_set, null_set)

                                    # update NAT rules by sending PreRulebase object (e.g. grandchild)
                                    update_objects(pre_nats, grandchild, 'Device Group', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), dg_rule_names, dg_zone_names, dg_nat_names, dg_interface_names, null_set, null_set)

                                if issubclass(type(grandchild), PostRulebase):
                                    # update Rules by sending PostRulebase object (e.g. grandchild)
                                    update_objects(post_rules, grandchild, 'Device Group', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), dg_rule_names, dg_zone_names, dg_nat_names, dg_interface_names, null_set, null_set)

                                    # update NAT rules by sending PostRulebase object (e.g. grandchild)
                                    update_objects(post_nats, grandchild, 'Device Group', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), dg_rule_names, dg_zone_names, dg_nat_names, dg_interface_names, null_set, null_set)

                            # perform Deletions
                            update_objects(deletions, child, 'Device Group', child.name, action, args, logger, filename, failures, dg_tag_names, dg_address_names, dg_address_group_names, dg_service_names, dg_service_group_names, dg_application_names, dg_application_group_names, dg_rule_names, dg_zone_names, dg_nat_names, dg_interface_names, dg_route_names, null_set)

                            # perform Edits
                            update_objects(edits, child, 'Device Group', child.name, action, args, logger, filename, failures, dg_tag_names, dg_address_names, dg_address_group_names, dg_service_names, dg_service_group_names, dg_application_names, dg_application_group_names, dg_rule_names, dg_zone_names, dg_nat_names, dg_interface_names, dg_route_names, null_set)

                            # perform Group Modifications
                            update_objects(modifications, child, 'Device Group', child.name, action, args, logger, filename, failures, dg_tag_names, dg_address_names, dg_address_group_names, dg_service_names, dg_service_group_names, dg_application_names, dg_application_group_names, dg_rule_names, dg_zone_names, dg_nat_names, dg_interface_names, dg_route_names, null_set)

                            # what about virtual systems, zones, virtual routers, interfaces?

                    else:
                        if not args.quiet:
                            logger.info('No dbedit file supplied. No update possible for Device Group \'{}\'.'.format(child.name))
        else:

            ###############################################################################
            #
            # we are at the global level, perform global level activities - dbedit objects must have location = 'global'
            #
            ###############################################################################

            if not args.quiet:
                logger.info('Global Object Level: \'{}\''.format(pano.hostname))
            filename = get_palo_filename(pano, args, logger)

            ###############################################################################
            #
            # Collect Global and PreDefined Objects only if required
            #
            ###############################################################################

            if args.output or (args.filename and not args.no_checks):

                # collect Global Objects
                if args.verbose:
                    logger.info('Collecting Global Objects from Panorama \'{}\''.format(pano.hostname))

                all_global_objects, G_address_names, G_address_group_names, G_application_names, G_application_group_names, G_application_container_names, G_application_filter_names, G_service_names, G_service_group_names, G_tag_names = get_palo_objects(pano, args, logger)

                # collect Pre-Defined Objects
                if args.verbose:
                    logger.info('Collecting Predefined Objects from Panorama \'{}\''.format(pano.hostname))

                pd_live_application_names, pd_live_application_container_names, pd_live_service_names, pd_live_tag_names = get_palo_predefined_objects(pano, args, logger)

                # collect Global objects from dbedit file
                if args.filename and not args.no_checks:
                    a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, dbedit_addresses, dbedit_address_groups, dbedit_services, dbedit_service_groups, dbedit_tags, dbedit_applications, dbedit_application_groups, dbedit_application_filter_names, dbedit_pre_rules, dbedit_pre_nats, dbedit_post_rules, dbedit_post_nats, dbedit_deletions, dbedit_edits, dbedit_modifications, dbedit_static_routes, dbedit_dips = get_dbedit_actions(dbedit_objects, dbedit_pano_pre_rules, dbedit_pano_post_rules, 'palo', 'global', 'create', 'Panorama', args, logger)

            ##############################################################################
            #
            # write objects output files as requested
            #
            ###############################################################################

            if args.output:
                write_objects_dbedit_csv(filename + '_apidata-' + t, 'Panorama Shared Objects', all_global_objects, None, pano.hostname, 'write', args, logger)

            ###############################################################################
            #
            # print objects/rules to console as requested
            #
            ###############################################################################

            if args.verbose == 2:
                print_palo_objects_list(pano.hostname + ' All Global Objects', all_global_objects, logger)

            ###############################################################################
            #
            # Assess updates to Panorama Global Objects from dbedit
            #
            ###############################################################################

            if args.filename:

                if not args.quiet:
                    logger.info('Panorama \'{}\' dbedit update checking...'.format(pano.hostname))

                ###############################################################################
                #
                # Combine Global Object names sets with Predefined object names sets
                #
                ###############################################################################

                if not args.no_checks:

                    global_tag_names = pd_live_tag_names.union(G_tag_names)
                    global_application_names = pd_live_application_names.union(G_application_names)
                    global_application_container_names = pd_live_application_container_names.union(G_application_container_names)
                    global_service_names = pd_live_service_names.union(G_service_names)

                    available_address_names = G_address_names
                    available_address_group_names = G_address_group_names
                    available_application_names = global_application_names.union(global_application_container_names)
                    available_application_group_names = G_application_group_names
                    available_application_filter_names = G_application_filter_names
                    available_service_names = global_service_names
                    available_service_group_names = G_service_group_names
                    available_tag_names = global_tag_names

                else:

                    available_address_names = set()
                    available_address_group_names = set()
                    available_application_names = set()
                    available_application_group_names = set()
                    available_application_filter_names = set()
                    available_service_names = set()
                    available_service_group_names = set()
                    available_tag_names = set()

                ###############################################################################
                #
                # dbedit file was already parsed - extract dbedit instructions per action type specific to Panorama
                #
                ###############################################################################

                for action in csv_action_types:

                    addresses, address_groups, services, service_groups, tags, applications, application_groups, pre_rules, post_rules, pre_nats, post_nats, deletions, edits, modifications, static_routes, dips, dbedit_addresses, dbedit_address_groups, dbedit_services, dbedit_service_groups, dbedit_tags, dbedit_applications, dbedit_application_groups, dbedit_application_filter_names, dbedit_pre_rules, dbedit_pre_nats, dbedit_post_rules, dbedit_post_nats, dbedit_deletions, dbedit_edits, dbedit_modifications, dbedit_static_routes, dbedit_dips = get_dbedit_actions(dbedit_objects, dbedit_pano_pre_rules, dbedit_pano_post_rules, 'palo', 'global', action, 'Panorama', args, logger)

                    ###############################################################################
                    #
                    # Create all the objects ensuring specific creation order - DO NOT 'union' with dbedit for the object being created!
                    #
                    ###############################################################################

                    # update Tags
                    update_objects(tags, pano, 'Panorama', pano.hostname, action, args, logger, filename, failures, available_tag_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                    # update Addresses
                    update_objects(addresses, pano, 'Panorama', pano.hostname, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                    # update Address Groups
                    update_objects(address_groups, pano, 'Panorama', pano.hostname, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                    # update Services
                    update_objects(services, pano, 'Panorama', pano.hostname, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), null_set, null_set, available_service_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                    # update Service Groups
                    update_objects(service_groups, pano, 'Panorama', pano.hostname, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), null_set, null_set, available_service_names.union(dbedit_services), available_service_group_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                    # update Applications
                    update_objects(applications, pano, 'Panorama', pano.hostname, action, args, logger, filename, failures, null_set, null_set, null_set, null_set, null_set, available_application_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                    # update Application Groups
                    update_objects(application_groups, pano, 'Panorama', pano.hostname, action, args, logger, filename, failures, null_set, null_set, null_set, null_set, null_set, available_application_names.union(dbedit_applications), available_application_group_names, null_set, null_set, null_set, null_set, null_set, null_set)

                    # perform Deletions
                    update_objects(deletions, pano, 'Panorama', pano.hostname, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), null_set, null_set, null_set, null_set, null_set, null_set)

                    # perform Edits
                    update_objects(edits, pano, 'Panorama', pano.hostname, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), null_set, null_set, null_set, null_set, null_set, null_set)

                    # perform Group Modifications
                    update_objects(modifications, pano, 'Panorama', pano.hostname, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), null_set, null_set, null_set, null_set, null_set, null_set)

            else:
                if not args.quiet:
                    logger.info('No dbedit file supplied. No update possible for Panorama \'{}\'.'.format(pano.hostname))

        ###############################################################################
        #
        # Commit and Release Configuration/Commit Locks
        #
        ###############################################################################

        tidy_up(pano, failures, args, logger)

    ###############################################################################
    #
    # Firewall section
    #
    ###############################################################################

    if issubclass(type(device), Firewall):

        ###############################################################################
        #
        # make the fw object, set the output filename and state the obvious
        #
        ###############################################################################

        if not args.quiet:
            logger.info('Connecting to Firewall \'{}\''.format(args.device))

        try:
            fw = Firewall(args.device, args.username, args.password)
        except Exception as e:
            logger.error('Cannot open API to device \'{}\', ({}) exiting...'.format(args.device, neutralise_newlines(repr(e), args, logger)))
            for email in emails:
                send_email(email_subject, email + __email_domain__, logfile, email_message, args, logger)
            sys.exit(1)

        filename = get_palo_filename(fw, args, logger)

        ###############################################################################
        #
        # Take Configuration/Commit Locks
        #
        ###############################################################################

        if args.filename and not args.test and not args.no_locks:
            take_locks(fw, args, logger)

        ###############################################################################
        #
        # Collect Firewall level information: Zones, Virtual-Routers, Interfaces, Pre-Defined objects
        #
        ###############################################################################

        zones, vrouters, live_zone_names, live_vrouter_names = get_palo_network(fw, args, logger)

        if args.output or (args.filename and not args.no_checks):

            phy_interfaces, sub_interfaces, vpn_interfaces, loop_interfaces, vlan_interfaces, agg_interfaces, live_phy_interfaces_names, live_sub_interfaces_names, live_vpn_interfaces_names, live_loop_interfaces_names, live_vlan_interfaces_names, live_agg_interfaces_names, all_interfaces = get_palo_interfaces(fw, args, logger)
            pd_live_application_names, pd_live_application_container_names, pd_live_service_names, pd_live_tag_names = get_palo_predefined_objects(fw, args, logger)

        else:

            phy_interfaces = set()
            sub_interfaces = set()
            vpn_interfaces = set()
            vlan_interfaces = set()
            agg_interfaces = set()
            live_phy_interfaces_names = set()
            live_sub_interfaces_names = set()
            live_vpn_interfaces_names = set()
            live_loop_interfaces_names = set()
            live_vlan_interfaces_names = set()
            live_agg_interfaces_names = set()
            all_interfaces = set()
            pd_live_application_names = set()
            pd_live_application_container_names = set()
            pd_live_service_names = set()
            pd_live_tag_names = set()

        ###############################################################################
        #
        # Collect StaticRoute objects per VRF
        #
        ###############################################################################

        for vrouter in vrouters:

            if args.output or (args.filename and not args.no_checks):

                vrf_static_routes, vrf_static_route_names = get_palo_routes(vrouter, args, logger)

            else:

                vrf_static_routes = set()
                vrf_static_route_names = set()

            ###############################################################################
            #
            # write StaticRoutes to file as requested
            #
            ###############################################################################

            if args.output:
                write_objects_dbedit_csv(filename + '_apidata-' + t, 'VRF Static Routes', vrf_static_routes, 'route', vrouter.name, 'append', args, logger)

            ###############################################################################
            #
            # print StaticRoutes to console as requested
            #
            ###############################################################################

            if args.verbose == 2:
                if vrf_static_routes:
                    for vrf_static_route in vrf_static_routes:
                        print_palo_object(vrf_static_route, logger)
                else:
                    logger.info('Virtual Router \'{}\' contains zero Routes'.format(vrouter.name))

            ###############################################################################
            #
            # update any StaticRoutes
            #
            ###############################################################################

            if args.filename:

                for action in csv_action_types:

                    addresses, address_groups, services, service_groups, tags, applications, application_groups, pre_rules, post_rules, pre_nats, post_nats, deletions, edits, modifications, static_routes, dips, dbedit_addresses, dbedit_address_groups, dbedit_services, dbedit_service_groups, dbedit_tags, dbedit_applications, dbedit_application_groups, dbedit_application_filter_names, dbedit_pre_rules, dbedit_pre_nats, dbedit_post_rules, dbedit_post_nats, dbedit_deletions, dbedit_edits, dbedit_modifications, dbedit_static_routes, dbedit_dips = get_dbedit_actions(dbedit_objects, dbedit_pano_pre_rules, dbedit_pano_post_rules, 'palo', vrouter.name, action, 'VRF', args, logger)

                    # update StaticRoute
                    update_objects(static_routes, vrouter, 'Virtual Router', vrouter.name, action, args, logger, filename, failures, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, vrf_static_route_names, null_set)

                    # perform Deletions
                    update_objects(deletions, vrouter, 'Virtual Router', vrouter.name, action, args, logger, filename, failures, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, vrf_static_route_names, null_set)

        ###############################################################################
        #
        # figure out which Vsys are in scope
        #
        ###############################################################################

        if fw.multi_vsys:

            # this will add all VSYS to the 'fw' tree as well
            try:
                vsys = Vsys.refreshall(fw)

                if args.verbose:
                    for v in vsys:
                        if not args.quiet:
                            logger.info('Live Device: Found VSYS \'{}\' ({})'.format(v.name, v.display_name))

                if (args.location):
                    if args.location == 'ALL':
                        if not args.quiet:
                            logger.info('ALL VSYS requested in scope')
                    else:
                        # check that the location provided actually exists
                        for v in vsys:
                            if v.name == args.location:
                                if not args.quiet:
                                    logger.info('Matched VSYS \'{}\' with supplied argument'.format(args.location))
                                break
                        else:
                            logger.error('VSYS \'{}\' is not found, exiting...'.format(args.location))
                            for email in emails:
                                send_email(email_subject, email + __email_domain__, logfile, email_message, args, logger)
                            if args.filename and not args.test and not args.no_locks:
                                release_locks(fw, args, logger)
                            sys.exit(1)

                        # remove unwanted VSYS objects from the 'fw' tree
                        for v in vsys:
                            if v.name != args.location:
                                fw.remove(v)
                                if args.verbose == 2:
                                    logger.info('Removed VSYS \'{}\' from tree'.format(v.name))
                else:
                    # need to remove all other VSYS and add VSYS1 to 'fw' tree
                    for v in vsys:
                        fw.remove(v)
                        if args.verbose == 2:
                            logger.info('Removed VSYS \'{}\' from tree'.format(v.name))

                    # else assume vsys1...
                    vsys1 = Vsys('vsys1')
                    fw.add(vsys1)

            except Exception as e:
                logger.error('Cannot refresh VSYS for device \'{}\', ({}) exiting...'.format(fw.hostname, neutralise_newlines(repr(e), args, logger)))

        else:
            # we must be single VSYS only
            vsys1 = Vsys('vsys1')
            fw.add(vsys1)

        ###############################################################################
        #
        # need to collect Shared objects here and combine into 'sets' with pre-defined objects
        #
        ###############################################################################

        shared = Vsys('shared')
        fw.add(shared)

        for child in fw.children:
            if issubclass(type(child), Vsys):
                if child.name == 'shared':

                    if args.output or (args.filename and not args.no_checks):

                        all_shared_objects, shared_address_names, shared_address_group_names, shared_application_names, shared_application_group_names, shared_application_container_names, shared_application_filter_names, shared_service_names, shared_service_group_names, shared_tag_names = get_palo_objects(child, args, logger)

                    else:

                        all_shared_objects = set()
                        shared_address_names = set()
                        shared_address_group_names = set()
                        shared_application_names = set()
                        shared_application_group_names = set()
                        shared_application_container_names = set()
                        shared_application_filter_names = set()
                        shared_service_names = set()
                        shared_service_group_names = set()
                        shared_tag_names = set()

                    ###############################################################################
                    #
                    # write objects/rules output files as requested
                    #
                    ###############################################################################

                    if args.output:
                        write_objects_dbedit_csv(filename + '_apidata-' + t, 'Firewall Shared Objects', all_shared_objects, None, child.name, 'append', args, logger)

                    ###############################################################################
                    #
                    # print objects/rules to console as requested
                    #
                    ###############################################################################

                    if args.verbose == 2:
                        print_palo_objects_list(filename + ' All Shared Objects', all_shared_objects, logger)

                    ###############################################################################
                    #
                    # Assess updates to Shared objects from dbedit
                    #
                    ###############################################################################

                    if args.filename:

                        if not args.quiet:
                            logger.info('VSYS \'{}\': dbedit update checking...'.format(child.name))

                        ###############################################################################
                        #
                        # Combine all the various Shared object names with the pre-defined results into sets
                        #
                        ###############################################################################

                        if not args.no_checks:

                            def_application_names = pd_live_application_names.union(shared_application_names)
                            def_application_container_names = pd_live_application_container_names.union(shared_application_container_names)
                            def_service_names = pd_live_service_names.union(shared_service_names)
                            def_tag_names = pd_live_tag_names.union(shared_tag_names)

                            available_address_names = shared_address_names
                            available_address_group_names = shared_address_group_names
                            available_application_names = def_application_names.union(def_application_container_names)
                            available_application_group_names = shared_application_group_names
                            available_application_filter_names = shared_application_filter_names
                            available_service_names = def_service_names
                            available_service_group_names = shared_service_group_names
                            available_tag_names = def_tag_names

                        else:

                            available_address_names = set()
                            available_address_group_names = set()
                            available_application_names = set()
                            available_application_group_names = set()
                            available_application_filter_names = set()
                            available_service_names = set()
                            available_service_group_names = set()
                            available_tag_names = set()

                        ###############################################################################
                        #
                        # dbedit file was already parsed - extract dbedit instructions per action type specific to Vsys
                        #
                        ###############################################################################

                        for action in csv_action_types:

                            addresses, address_groups, services, service_groups, tags, applications, application_groups, pre_rules, post_rules, pre_nats, post_nats, deletions, edits, modifications, static_routes, dips, dbedit_addresses, dbedit_address_groups, dbedit_services, dbedit_service_groups, dbedit_tags, dbedit_applications, dbedit_application_groups, dbedit_application_filter_names, dbedit_pre_rules, dbedit_pre_nats, dbedit_post_rules, dbedit_post_nats, dbedit_deletions, dbedit_edits, dbedit_modifications, dbedit_static_routes, dbedit_dips = get_dbedit_actions(dbedit_objects, dbedit_pano_pre_rules, dbedit_pano_post_rules, 'palo', child.name, action, 'Firewall', args, logger)

                            ###############################################################################
                            #
                            # Create all the objects ensuring specific creation order - DO NOT 'union' with dbedit for the object being created!
                            #
                            ###############################################################################

                            # update Tags
                            update_objects(tags, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Addresses
                            update_objects(addresses, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Address Groups
                            update_objects(address_groups, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Services
                            update_objects(services, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), null_set, null_set, available_service_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Service Groups
                            update_objects(service_groups, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), null_set, null_set, available_service_names.union(dbedit_services), available_service_group_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Applications
                            update_objects(applications, child, 'Firewall', child.name, action, args, logger, filename, failures, null_set, null_set, null_set, null_set, null_set, available_application_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                            # update Application Groups
                            update_objects(application_groups, child, 'Firewall', child.name, action, args, logger, filename, failures, null_set, null_set, null_set, null_set, null_set, available_application_names.union(dbedit_applications), available_application_group_names, null_set, null_set, null_set, null_set, null_set, null_set)

                            # perform Deletions
                            update_objects(deletions, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), null_set, null_set, null_set, null_set, null_set, null_set)

                            # perform Edits
                            update_objects(edits, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), null_set, null_set, null_set, null_set, null_set, null_set)

                            # perform Group Modifications
                            update_objects(modifications, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), null_set, null_set, null_set, null_set, null_set, null_set)

                    else:
                        if not args.quiet:
                            logger.info('No dbedit file supplied. No update possible for VSYS \'{}\'.'.format(child.name))

        fw.remove(shared)

        ###############################################################################
        #
        # iterate over the Vsys objects and write/print/update as requested
        #
        ###############################################################################

        for child in fw.children:
            if issubclass(type(child), Vsys):

                # make useful name to map vsys number to name
                if child.display_name is not None:
                    full_vsys_name = '__'.join([child.name, child.display_name])
                else:
                    full_vsys_name = child.name

                if args.output or args.filename:
                    try:
                        vsys_fw = Firewall(args.device, args.username, args.password, vsys=child.name)
                        registered_ips, dip_names = get_palo_dips(vsys_fw, args, logger)

                    except Exception as e:
                        logger.error('Cannot create VSYS version of firewall \'{}\', ({}). This will affect DIPs! exiting...'.format(child.name, neutralise_newlines(repr(e), args, logger)))
                else:
                    registered_ips = set()
                    dip_names = set()

                ###############################################################################
                #
                # get 'lists' and 'sets' from device API of all Objects and Rules and combine with the predefined objects
                #
                ###############################################################################

                if args.output or (args.filename and not args.no_checks):

                    # collect zones for this VSYS
                    zones, vsys_zone_names = get_palo_zones(child, args, logger)
                    vs_all_live_objects, vs_live_address_names, vs_live_address_group_names, vs_live_application_names, vs_live_application_group_names, vs_live_application_container_names, vs_live_application_filter_names, vs_live_service_names, vs_live_service_group_names, vs_live_tag_names = get_palo_objects(child, args, logger)
                    sec_rules, nat_rules, vsys_rule_names, vsys_nat_names = get_palo_fw_rules(child, args, logger)
                    all_live_objects = list(set(vs_all_live_objects))

                else:

                    zones = set()
                    vsys_zone_names = set()
                    vs_all_live_objects = set()
                    vs_live_address_names = set()
                    vs_live_address_group_names = set()
                    vs_live_application_names = set()
                    vs_live_application_group_names = set()
                    vs_live_application_container_names = set()
                    vs_live_application_filter_names = set()
                    vs_live_service_names = set()
                    vs_live_service_group_names = set()
                    vs_live_tag_names = set()
                    sec_rules = set()
                    nat_rules = set()
                    vsys_rule_names = set()
                    vsys_nat_names = set()
                    all_live_objects = set()

                ###############################################################################
                #
                # write objects/rules output files as requested
                #
                ###############################################################################

                if args.output:
                    write_objects_dbedit_csv(filename + '_apidata-' + t, 'VSYS Objects', all_live_objects, None, full_vsys_name, 'append', args, logger)
                    write_objects_dbedit_csv(filename + '_apidata-' + t, 'VSYS Security Rules', sec_rules, 'security-rule', full_vsys_name, 'append', args, logger)
                    write_objects_dbedit_csv(filename + '_apidata-' + t, 'VSYS NAT Rules', nat_rules, 'nat-rule', full_vsys_name, 'append', args, logger)
                    write_objects_dbedit_csv(filename + '_apidata-' + t, 'Registered IPs', registered_ips, 'dip', full_vsys_name, 'append', args, logger)

                ###############################################################################
                #
                # print objects/rules to console as requested
                #
                ###############################################################################

                if args.verbose == 2:
                    print_palo_objects_list(full_vsys_name + ' Security Rules', sec_rules, logger)
                    print_palo_objects_list(full_vsys_name + ' NAT Rules', nat_rules, logger)
                    print_palo_objects_list(full_vsys_name + ' Objects', all_live_objects, logger)
                    print_palo_objects_list(full_vsys_name + ' Dynamic IPs', registered_ips, logger)

                ###############################################################################
                #
                # Assess updates to VSYS from dbedit
                #
                ###############################################################################

                if args.filename:

                    if not args.quiet:
                        logger.info('VSYS \'{}\': dbedit update checking...'.format(child.name))

                    ###############################################################################
                    #
                    # Combine all the various object names Shared, VSYS, DBedit into sets
                    #
                    ###############################################################################

                    if not args.no_checks:

                        available_address_names = vs_live_address_names.union(shared_address_names)
                        available_address_group_names = vs_live_address_group_names.union(shared_address_group_names)
                        staged_application_names = vs_live_application_names.union(def_application_names)
                        available_application_group_names = vs_live_application_group_names.union(shared_application_group_names)
                        available_application_container_names = vs_live_application_container_names.union(def_application_container_names)
                        available_application_filter_names = vs_live_application_filter_names.union(shared_application_filter_names)
                        available_service_names = vs_live_service_names.union(def_service_names)
                        available_service_group_names = vs_live_service_group_names.union(shared_service_group_names)
                        available_tag_names = vs_live_tag_names.union(def_tag_names)
                        available_application_names = staged_application_names.union(available_application_container_names)

                    else:

                        available_address_names = set()
                        available_address_group_names = set()
                        available_application_names = set()
                        available_application_group_names = set()
                        available_application_container_names = set()
                        available_application_filter_names = set()
                        available_service_names = set()
                        available_service_group_names = set()
                        available_tag_names = set()

                    ###############################################################################
                    #
                    # dbedit file was already parsed - extract dbedit instructions per action type specific to Vsys
                    #
                    ###############################################################################

                    for action in csv_action_types:

                        addresses, address_groups, services, service_groups, tags, applications, application_groups, pre_rules, post_rules, pre_nats, post_nats, deletions, edits, modifications, static_routes, dips, dbedit_addresses, dbedit_address_groups, dbedit_services, dbedit_service_groups, dbedit_tags, dbedit_applications, dbedit_application_groups, dbedit_application_filter_names, dbedit_pre_rules, dbedit_pre_nats, dbedit_post_rules, dbedit_post_nats, dbedit_deletions, dbedit_edits, dbedit_modifications, dbedit_static_routes, dbedit_dips = get_dbedit_actions(dbedit_objects, dbedit_pano_pre_rules, dbedit_pano_post_rules, 'palo', child.name, action, 'VSYS', args, logger)

                        ###############################################################################
                        #
                        # Create all the objects ensuring specific creation order - DO NOT 'union' with dbedit for the object being created!
                        #
                        ###############################################################################

                        # update Tags
                        update_objects(tags, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                        # update Dynamic IPs
                        try:
                            vsys_fw.userid.batch_start()
                            update_objects(dips, vsys_fw, 'DIP', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, dip_names)
                            vsys_fw.userid.batch_end()
                        except Exception as e:
                            logger.error('Cannot batch config for device \'{}\', ({}).'.format(child.name, neutralise_newlines(repr(e), args, logger)))

                        # update Addresses
                        update_objects(addresses, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                        # update Address Groups
                        update_objects(address_groups, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                        # update Services
                        update_objects(services, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), null_set, null_set, available_service_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                        # update Service Groups
                        update_objects(service_groups, child, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), null_set, null_set, available_service_names.union(dbedit_services), available_service_group_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                        # update Applications
                        update_objects(applications, child, 'Firewall', child.name, action, args, logger, filename, failures, null_set, null_set, null_set, null_set, null_set, available_application_names, null_set, null_set, null_set, null_set, null_set, null_set, null_set)

                        # update Application Groups
                        update_objects(application_groups, child, 'Firewall', child.name, action, args, logger, filename, failures, null_set, null_set, null_set, null_set, null_set, available_application_names.union(dbedit_applications), available_application_group_names, null_set, null_set, null_set, null_set, null_set, null_set)

                        # update Security and NAT rules - don't forget the hierarchy here, VSYS->Rulebase->SecurityRule/NatRule
                        for grandchild in child.children:

                            if args.verbose == 3:
                                logger.debug('VSYS Child {}'.format(str(type(grandchild))))

                            if issubclass(type(grandchild), Rulebase):
                                # update Rules by sending Rulebase object (e.g. grandchild)
                                update_objects(pre_rules, grandchild, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), vsys_rule_names, vsys_zone_names, vsys_nat_names, all_interfaces, null_set, null_set)

                                # update NAT rules by sending Rulebase object (e.g. grandchild)
                                update_objects(pre_nats, grandchild, 'Firewall', child.name, action, args, logger, filename, failures, available_tag_names.union(dbedit_tags), available_address_names.union(dbedit_addresses), available_address_group_names.union(dbedit_address_groups), available_service_names.union(dbedit_services), available_service_group_names.union(dbedit_service_groups), available_application_names.union(dbedit_applications), available_application_group_names.union(dbedit_application_groups), vsys_rule_names, vsys_zone_names, vsys_nat_names, all_interfaces, null_set, null_set)

                        # perform Deletions
                        update_objects(deletions, child, 'Firewall', child.name, action, args, logger, filename, failures, vs_live_tag_names, vs_live_address_names, vs_live_address_group_names, vs_live_service_names, vs_live_service_group_names, vs_live_application_names, vs_live_application_group_names, vsys_rule_names, vsys_zone_names, vsys_nat_names, all_interfaces, null_set, null_set)

                        # perform Edits
                        update_objects(edits, child, 'Firewall', child.name, action, args, logger, filename, failures, vs_live_tag_names, vs_live_address_names, vs_live_address_group_names, vs_live_service_names, vs_live_service_group_names, vs_live_application_names, vs_live_application_group_names, vsys_rule_names, vsys_zone_names, vsys_nat_names, all_interfaces, null_set, null_set)

                        # perform Group Modifications
                        update_objects(modifications, child, 'Firewall', child.name, action, args, logger, filename, failures, vs_live_tag_names, vs_live_address_names, vs_live_address_group_names, vs_live_service_names, vs_live_service_group_names, vs_live_application_names, vs_live_application_group_names, vsys_rule_names, vsys_zone_names, vsys_nat_names, all_interfaces, null_set, null_set)

                else:
                    if not args.quiet:
                        logger.info('No dbedit file supplied. No update possible for VSYS \'{}\'.'.format(child.name))

        ###############################################################################
        #
        # Commit and Release Configuration/Commit Locks
        #
        ###############################################################################

        tidy_up(fw, failures, args, logger)

    ###############################################################################
    #
    # Print failures and email out logfile
    #
    ###############################################################################

    if failures:
        for f in failures:
            logger.error('API update failure for: \'{}\''.format(f))
            email_message += 'API update failure for: \'{}\'\n'.format(f)

    else:
        if not args.quiet:
            logger.info('AMAZING! No API update failures detected ;)')
        email_message += 'AMAZING! No API failures detected ;)\n'

    for email in emails:
        send_email(email_subject, email + __email_domain__, logfile, email_message, args, logger)

if __name__ == '__main__':
    main()

