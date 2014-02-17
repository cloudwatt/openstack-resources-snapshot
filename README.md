snapshot: Lists OpenStack resources in a project
============================================

`snapshot` is a client side script allowing an OpenStack user to list resources that are deployed/available in his/her project.

Installation
------------

Get `snapshot` source code:

    $ git clone https://github.com/cloudwatt/openstack-resources-snapshot.git

This script uses the OpenStack clients to connect to the services and retrieve all information about resources that where deployed in the project.

These clients can be installed by using the `requirements.txt` if they are not already available:

    $ sudo pip install -r requirements.txt


Usage
-----

Available options can be displayed by using `snapshot.py -h`:

    $python snapshot.py  --help
    usage: snapshot.py [-h] username password project auth_url

    Print resources from an Openstack project or user

    positional arguments:
        username    A user name with access to the project
        password    The user's password
        project     Name of project
        auth_url    Authentication URL

    optional arguments:
    -h, --help  show this help message and exit

Example
-------
    $ python snapshot.py arezmerita password project-arezmerita https://identity0.cw-labs.net/v2.0/

Listed resources
-------

The following resources will be listed:

* instances
* volumes/volumes snapshots
* tenant images/snapshots
* security groups/rules
* key pairs
* routers
* networks


License / Copyright
-------------------

This software is released under the MIT License.

Copyright (c) 2014 Cloudwatt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
