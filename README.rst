|Stable| |Tag| |License| |Build| |Coverage|

.. raw:: html

  <div align="center">
    <h1><code>hackinsdn/containment</code></h1>

    <strong>Kytos-ng Napp that allows attacks containment</strong>
  </div>


Overview
========


In cybersecurity, attack containment refer to the practices and technologies used
to mitigate, isolate, or limit the impact of cyber threats in a network or system
during the handling of a security event.
This Napp brings the cyberattack containment capabilities to Kytos-ng, and allows
several containment strategy:

- Traffic blocking
- Redirect
- Rate limit

Getting started
===============

To install this NApp, first, make sure to have the same venv activated as you have ``kytos`` installed on:

.. code:: shell

   $ git clone https://github.com/hackinsdn/containment.git
   $ cd containment
   $ python3 setup.py develop

Other possible ways of installing this Napp would be:
- Using pip with github repo URL (you may want to change the branch from main to something else): `python3 -m pip install -e git+http://github.com/hackinsdn/containment@main#egg=hackinsdn-containment`
- Using pip with local repo copy: `git clone http://github.com/hackinsdn/containment && cd containment && python3 -m pip install -e .`

The easiest way of using this Napp is through the Docker container:

.. code:: shell

   $ docker pull hackinsdn/kytos:latest
   $ docker run -d --name mongo mongo:7.0
   $ docker exec -it mongo mongo --eval 'db.getSiblingDB("kytos").createUser({user: "kytos", pwd: "kytos", roles: [ { role: "dbAdmin", db: "kytos" } ]})'
   $ docker run -d --name kytos --link mongo -v /lib/modules:/lib/modules --privileged -e MONGO_DBNAME=kytos -e MONGO_USERNAME=kytos -e MONGO_PASSWORD=kytos -e MONGO_HOST_SEEDS=mongo:27017 -p 8181:8181  hackinsdn/kytos:latest

Requirements
============

- `kytos/of_core <https://github.com/kytos-ng/of_core>`_
- `kytos/flow_manager <https://github.com/kytos-ng/flow_manager>`_


General Information
===================

The Containment Napp supports TODO, TODO

- To create a containment to block traffic from IPv4 10.1.98.100 on VLAN 198 at the switch 00:00:00:00:00:00:00:01 port 1, one would have to run the following command:

.. code-block:: shell

	# curl -s -X POST -H 'Content-type: application/json' http://127.0.0.1:8181/api/hackinsdn/containment/v1/ -d '{"switch": "00:00:00:00:00:00:00:01", "interface": 1, "match": {"vlan": 198, "ipv4_src": "10.1.98.100"}}'
	{"containment_id": "ad80c44576c84d"}

- To list existing containments, one would have to run the following command:

.. code-block:: shell

 	# curl -s http://127.0.0.1:8181/api/hackinsdn/containment/v1/
	{
	  "blocks": {
	    "6ca46d899ff14f": {
	      "switch": "00:00:00:00:00:00:00:01",
	      "interface": 1,
	      "match": {
	        "vlan": 198,
	        "ipv4_src": "10.1.98.100"
	      }
	    }
	  }
	}

- To delete a containment:

.. code-block:: shell

 	# curl -s -X DELETE http://127.0.0.1:8181/api/hackinsdn/containment/v1/6ca46d899ff14f



.. TAGs

.. |Stable| image:: https://img.shields.io/badge/stability-stable-green.svg
   :target: https://github.com/hackinsdn/containment
.. |Build| image:: https://github.com/hackinsdn/containment/actions/workflows/test.yml/badge.svg
  :alt: Build status
.. |Coverage| image:: https://coveralls.io/repos/github/containment/mirror/badge.svg
  :alt: Code coverage
.. |Tag| image:: https://img.shields.io/github/tag/hackinsdn/containment.svg
   :target: https://github.com/hackinsdn/containment/tags
.. |License| image:: https://img.shields.io/github/license/hackinsdn/containment.svg
   :target: https://github.com/hackinsdn/containment/blob/master/LICENSE
