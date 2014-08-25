#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#This software is released under the MIT License.
#
#Copyright (c) 2014 Ala Rezmerita <ala.rezmerita.cloudwatt.com> / Cloudwatt
# 	                Florent Flament <florent.flament-ext@cloudwatt.com> / Cloudwatt
#
#Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
# to whom the Software is furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all copies
#or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


import argparse
import logging
import prettytable

from cinderclient.v1 import client as cinder_client
from cinderclient import utils as cinder_utils
from glanceclient.v1 import client as glance_client
from glanceclient.common import utils as glance_utils
from keystoneclient.v2_0 import client as keystone_client
from neutronclient.v2_0 import client as neutron_client
from novaclient.v1_1 import client as nova_client
from novaclient.v1_1 import shell as nova_shell
from novaclient import utils as nova_utils


logging.basicConfig(level=logging.ERROR)


class ResourcePrinter(object):
    def __init__(self, *os_creds):
        self.nova = NovaManager(*os_creds)
        self.glance = GlanceManager(*os_creds)
        self.neutron = NeutronManager(*os_creds)
        self.cinder = CinderManager(*os_creds)

    def format_size(self, flavor):
        res = divmod(flavor.ram, 1024)
        if res[0] == 0:
            ram = ' '.join([str(res[1]) + 'MB', 'RAM'])
        else:
            ram = ' '.join([str(res[0]) + 'GB', 'RAM'])
        vcpus = ' '.join([str(flavor.vcpus), 'VCPU'])
        disk = ' '.join([str(flavor.disk) + 'GB', 'Disk'])
        return ' | '.join([flavor.name, ram, vcpus, disk])

    def format_networks(self, addresses):
        output = ''
        for net, addr in addresses.items():
            if len(addr) == 0:
                continue
            groupe = "%s=%s" % (net, addr[0]['addr'])
            if len(output):
                output = '%s, %s' % (output, groupe)
            else:
                output = '%s' % groupe
        return output

    def print_servers(self):
        table = prettytable.PrettyTable(['ID', 'Instance Name',
                                         'Status', 'Image Name',
                                         'Size', 'Key Pair',
                                         'Network'])
        for server in self.nova.server_list():
            image_name = self.glance.image_get(server.image['id']).name
            flavor = self.nova.flavor_get(server.flavor['id'])
            networks = self.format_networks(server.addresses)

            table.add_row([server.id,
                           server.name,
                           server.status,
                           image_name,
                           self.format_size(flavor),
                           server.key_name,
                           networks])
        print('\n\nINSTANCES')
        print(table)

    def print_volumes(self):
        columns = ['ID', 'Status', 'Display Name',
                   'Size', 'Volume Type', 'Bootable',
                   'Attached to']
        volumes = self.cinder.volume_list()
        for v in volumes:
            servers = [s.get('server_id') for s in v.attachments]
            setattr(v, 'attached_to', ','.join(map(str, servers)))
        print('\n\nVOLUMES')
        cinder_utils.print_list(volumes,
                                columns, {})
    def print_volumes_snapshots(self):
        columns = ['ID', 'Volume ID', 'Status', 'Display Name',
                  'Created at', 'Size']
        print('\n\nVOLUMES SNAPSHOTS')
        cinder_utils.print_list(self.cinder.snapshot_list(),
                                columns, {})

    def print_images(self):
        columns = ['ID', 'Name', 'Disk Format',
                   'Container Format', 'Size', 'Status']
        tenant_images = self.glance.image_list(owner=self.glance.project_id)
        snapshots = []
        images = []
        for image in tenant_images:
            if 'image_type' in image.properties:
                if image.properties['image_type'] == "snapshot":
                    snapshots.append(image)
            else:
                images.append(image)
        print('\n\nTENANT IMAGES')
        glance_utils.print_list(images, columns)

        print('\n\nTENANT SNAPSHOTS')
        glance_utils.print_list(snapshots, columns)

        tenant_images = self.glance.image_list()
        shared_images_ids = \
            self.glance.image_member_list(self.glance.project_id)

        print('\n\nSHARED IMAGES')
        tenant_images_1 = []
        for simg in shared_images_ids:
            for img in tenant_images:
                if img.id == simg.image_id:
                    tenant_images_1.append(img)
        glance_utils.print_list(tenant_images_1, columns)

        print('\n\nALL AVAILABLE IMAGES')
        tenant_images = self.glance.image_list()
        glance_utils.print_list(tenant_images, columns)

    def print_securitygr(self):
        columns = ['Direction', 'Ether Type', 'IP Protocol',
                   'Port Range', 'Remote']
        print('\n\nSECURITY GROUPS')

        secgr = self.nova.secgroup_list()
        for i in secgr:
            print("\nSecurity Group Name:%s\nDescription:%s" %
                  (i.name, i.description))
            nova_shell._print_secgroup_rules(i.rules)

    def print_keys(self):
        print('\n\nKEY PAIRS')
        columns = ['Name', 'Public Key']
        table = prettytable.PrettyTable(columns)
        table.hrules = prettytable.NONE
        table.align = "l"
        keypairs = self.nova.keypair_list()
        for keypair in keypairs:
            row = []
            row.append(keypair.name)
            row.append(keypair.public_key)
            table.add_row(row)

        print(table)
        #nova_utils.print_list(keypair, columns)

    def print_routers(self):
        routers = self.neutron.router_list()
        columns = ['ID', 'Name', 'External Gateway Info',
                   'Connected Networks(Ports) ']
        columns_networks = ['ID', 'Name', 'Subnet Name',
                            'Subnet ID', 'Subnet CIDR',
                            'DHCP', 'DNS nameservers',
                            'Allocation Pool']

        table = prettytable.PrettyTable(columns)
        table.hrules = prettytable.ALL

        table_networks = prettytable.PrettyTable(columns_networks)
        table_networks.hrules = prettytable.ALL

        subnets = self.neutron.subnet_list()
        networks = {}
        for net in self.neutron.network_list():
            row = []
            row.append(net['id'])
            row.append(net['name'])
            if len(net['subnets']):
                for subnet in subnets:
                    if subnet['id'] == net['subnets'][0]:
                        row.append(subnet['name'])
                        row.append(net['subnets'][0])
                        row.append(subnet['cidr'])
                        row.append(subnet['enable_dhcp'])
                        dns = ''
                        for d in subnet['dns_nameservers']:
                            if len(dns) == 0:
                                dns = d
                            else:
                                dns = ", ".join([dns, d])
                        row.append(dns)
                        
                        if subnet['allocation_pools'][0]:
                            row.append("start:%s end:%s" %
                                       (subnet['allocation_pools'][0]['start'],
                                        subnet['allocation_pools'][0]['end']))
            else:
                for i in range(0,6):
                    row.append('N/A')
            networks[net['id']] = net['name']
            table_networks.add_row(row)

        for router in routers:
            row = []
            row.append(router['id'])
            row.append(router['name'])
            external = router['external_gateway_info']
            if external is not None:
                row.append('%s:%s' % (networks[external['network_id']],
                                      external['network_id']))
            else:
                row.append(external)
            ports = self.neutron.router_interfaces_list(router)
            txt = ''
            for p in ports:
                if p['device_owner'] == 'network:router_interface':
                    network = "%s:%s" % (networks[p['network_id']],
                                         p['network_id'])
                    if len(txt) == 0:
                        txt = network
                    else:
                        txt = "%s\n%s" % (txt, network)
            row.append(txt)
            table.add_row(row)
        print('\n\nROUTERS')
        print(table)
        print('\n\nNETWORKS')
        print(table_networks)

    def run(self):
        self.print_servers()
        self.print_volumes()
        self.print_volumes_snapshots()
        self.print_images()
        self.print_securitygr()
        self.print_keys()
        self.print_routers()


class KeystoneManager(object):
    """Manages Keystone queries"""

    def __init__(self, username, password, project, auth_url):
        self.client = keystone_client.Client(
            username=username, password=password,
            tenant_name=project, auth_url=auth_url)

    def get_token(self):
        return self.client.auth_token

    def get_endpoint(self, service_type, endpoint_type="publicURL"):
        catalog = self.client.service_catalog.get_endpoints()
        return catalog[service_type][0][endpoint_type]

    def get_project_id(self):
        return self.client.tenant_id


class NovaManager(object):
    """Manage nova resources"""

    def __init__(self, username, password, project, auth_url):
        self.client = nova_client.Client(username, password, project, auth_url)

    def server_list(self):
        return self.client.servers.list()

    def secgroup_list(self):
        return self.client.security_groups.list()

    def floating_ip_list(self):
        return self.client.floating_ips.list()

    def flavor_get(self, id):
        return self.client.flavors.get(id)

    def keypair_list(self):
        return self.client.keypairs.list()


class CinderManager(object):
    """Manage Cinder resources"""

    def __init__(self, username, password, project, auth_url):
        self.client = cinder_client.Client(username,
                                           password,
                                           project,
                                           auth_url)

    def volume_list(self):
        return self.client.volumes.list()

    def snapshot_list(self):
        return self.client.volume_snapshots.list()


class GlanceManager(object):
    """Manage Glance resources"""

    def __init__(self, username, password, project, auth_url):
        keystone_mgr = KeystoneManager(username,
                                       password,
                                       project,
                                       auth_url)
        self.client = glance_client.Client(
            endpoint=keystone_mgr.get_endpoint("image"),
            token=keystone_mgr.get_token())
        self.project_id = keystone_mgr.get_project_id()

    def image_list(self, owner=None, is_public=None):
        return self.client.images.list(owner=owner, is_public=is_public)

    def image_member_list(self, member):
        return self.client.image_members.list(member=member)

    def image_get(self, id):
        return self.client.images.get(id)


class NeutronManager(object):
    def __init__(self, username, password, project, auth_url):
        self.client = neutron_client.Client(
            username=username, password=password,
            tenant_name=project, auth_url=auth_url)
        keystone_mgr = KeystoneManager(username, password, project, auth_url)
        self.project_id = keystone_mgr.get_project_id()

    def router_list(self):
        return filter(self._owned_resource,
                      self.client.list_routers()['routers'])

    def router_interfaces_list(self, router):
        return self.client.list_ports(device_id=router['id'])['ports']

    def network_list(self):
        return filter(self._owned_resource,
                      self.client.list_networks()['networks'])

    def subnet_list(self):
        return filter(self._owned_resource,
                      self.client.list_subnets()['subnets'])

    def _owned_resource(self, res):
        # Only considering resources owned by project
        return res['tenant_id'] == self.project_id


def main():
    desc = "Print resources from an Openstack project"
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("username", type=str, nargs=1,
                        help="A user name with access to the "
                             "project")
    parser.add_argument("password", type=str, nargs=1,
                        help="The user's password")
    parser.add_argument("project", type=str, nargs=1,
                        help="Name of project")
    parser.add_argument("auth_url", type=str, nargs=1,
                        help="Authentication URL")
    args = parser.parse_args()
    os_creds = (args.username[0], args.password[0],
                args.project[0], args.auth_url[0])

    ResourcePrinter(*os_creds).run()

if __name__ == "__main__":
    main()
