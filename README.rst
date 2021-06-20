====
aslcc
====

AWS SAML Login for CC

Based on [Mai by Henning Jacobs](https://github.com/hjacobs/mai)
This Python package provides some helper functions to allow programmatic retrieval of temporary AWS credentials with CC IDP.
This package requires Python 3.4


Installation
============

.. code-block:: bash

  # TBD!-->> Normal install drom PyPI           <<--!TBD
  # TBD!-->> sudo pip3 install --upgrade aslcc <<--!TBD
  # From GitHub
  pip install --upgrade --no-cache git+https://github.com/d-k-ivanov/aslcc@main
  # Locally
  git clone https://github.com/d-k-ivanov/aslcc
  pip install --upgrade --no-cache .


Usage
=====

.. code-block:: bash

  aslcc create <login_name>
  # Identity provider URL: https://adfs.ss.com/adfs/ls/idpinitiatedsignon
  # SAML username: yourname@ss.com
  # SAML password: yourpassword


Custom aws cli profile
======================

.. code-block:: bash

  aslcc create <login_name> --awsprofile <profile_name>
  aslcc login <login_name> --awsprofile <profile_name>

  aws --profile <profile_name>

