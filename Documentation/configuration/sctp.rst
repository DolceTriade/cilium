.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _sctp:

*******************
SCTP support (BETA)
*******************

Enabling
===================
Pass ``--set sctp.enabled=true`` to helm.

Limitations
===================
Cilium supports basic SCTP support. Specifically, the following is supported:
 - Pod <-> Pod communication
 - Pod <-> Service communication [*]

[*] SCTP support does not support rewriting ports for SCTP packets. This means
that when defining services, the targetPort **MUST** equal the port, otherwise
the packet will be dropped.

Cilium does not support the following:
 - Multihoming