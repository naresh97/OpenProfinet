.. OpenProfinet documentation master file, created by
   sphinx-quickstart on Wed Nov  3 17:59:48 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

OpenProfinet
=============

.. toctree::
   :maxdepth: 2
   :caption: Contents:



Installing
==========

The latest releases can be obtained on the `GitHub repository <https://github.com/naresh97/OpenProfinet/releases>`_ and installed as follows.

.. code-blocK:: console

   $ sudo apt install ./OpenProfinet-0.9.2-x86_64.deb

Building
--------

OpenProfinet is built using CMake. Simply pull the repository, and run CMake in the standard way.

.. code-block:: console

   $ git clone https://github.com/naresh97/OpenProfinet.git && cd ./OpenProfinet
   $ mkdir ./build && cd ./build
   $ cmake ..
   $ make

Pre-requisites
^^^^^^^^^^^^^^

The following pre-requisites are required for building. Ubuntu/Debian packages are specified, but packages on other
distributions should be installed in a similar way. Refer to your distribution's package manager.

.. code-block:: console

   $ sudo apt install libpcap-dev

Documentation
==================

ProfinetTool
------------

The ProfinetTool class provides a library of tools required for

.. doxygenclass:: ProfinetTool
   :members:

ProfinetDevice
--------------

.. doxygenstruct:: ProfinetDevice
   :members:
   :private-members:
   :undoc-members:


PCAP Interface
--------------

The PCAP Interface specified in pcapInterface.h provides the a C-based interface to the libpcap library.
Here, we listen, build and send packets to a specified interface, as well as process incoming packets on the
byte level.

.. doxygenfile:: pcapInterface.h

Licensing
=========

The source code and binaries of this project use the GPLv3 license for **non-commercial** uses only!

If you would like to use any part of the OpenProfinet project for commercial purposes, you must obtain
explicit permission from the `author <https://nareshkumarrao.com/contact/>`_.

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
