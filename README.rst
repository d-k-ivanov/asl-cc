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
  # TBD!-->> sudo pip3 install --upgrade aslcc  <<--!TBD
  # From GitHub
  python -m pip install --upgrade --no-cache --use-feature=in-tree-build git+https://github.com/d-k-ivanov/aslcc@main
  # Locally
  git clone https://github.com/d-k-ivanov/aslcc
  python -m pip install --upgrade --no-cache --use-feature=in-tree-build


Usage
=====

.. code-block:: bash

  aslcc create <profile_name>
  # Identity provider URL: https://adfs.ss.com/adfs/ls/idpinitiatedsignon
  # SAML username: yourname@ss.com
  # SAML password: yourpassword


Custom aws cli profile
======================

.. code-block:: bash

  aslcc create <profile_name>
  aslcc login  <profile_name> --awsprofile <aws_profile_name>

  aws --profile <profile_name>

