---

title: "Key Event Receipt Infrastructure (KERI)"
abbrev: "KERI"
docname: draft-ssmith-keri-latest
category: info

ipr: trust200902
area: TODO
workgroup: TODO Working Group
keyword: Internet-Draft

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    name: S. Smith
    organization: ProSapien LLC
    email: sam@prosapien.com

normative:

informative:
  KERI:
    target: https://arxiv.org/abs/1907.02143
    title: Key Event Receipt Infrastructure (KERI)
    author:
        ins: S. Smith
        name: Samuel M. Smith
        org: ProSapien LLC
    date: 2021

--- abstract

An identity system based secure overlay for the Internet is presented. This is based on a Key Event Receipt Infrastructure (KERI) or the [KERI] protocol. This includes a primary root-of-trust in self-certifying identifiers (SCIDs). It presents a formalism for Autonomic Identifiers (AIDs) and Autonomic Namespaces (ANs). They are part of an Autonomic Identity System (AIS). This system uses the design principle of minimally sufficient means to provide a candidate trust spanning layer for the internet. Associated with this system is a decentralized key management infrastructure (DKMI). The primary root-of-trust are self-certifying identifiers that are strongly bound at issuance to a cryptographic signing (public, private) key-pair. These are self-contained until/unless control needs to be transferred to a new key-pair. In that event an append only chained key-event log of signed transfer statements provides end verifiable control provenance. This makes intervening operational infrastructure replaceable because the event logs may be served up by any infrastructure including ambient infrastructure. End verifiable logs on ambient infrastructure enables ambient verifiability (verifiable by anyone, anywhere, at anytime). 
The primary key management operation is key rotation (transference) via a novel key pre-rotation scheme. Two primary trust modalities motivated the design, these are a direct (one-to-one) mode and an indirect (one-to-any) mode. The indirect mode depends on witnessed key event receipt logs (KERL) as a secondary root-of-trust for validating events. This gives rise to the acronym KERI for key event receipt infrastructure. In the direct mode, the identity controller establishes control via verified signatures of the controlling key-pair. The indirect mode extends that trust basis with witnessed key event receipt logs (KERL) for validating events. The security and accountability guarantees of indirect mode are provided by KA2CE or KERI’s Agreement Algorithm for Control Establishment among a set of witnesses. 
The KA2CE approach may be much more performant and scalable than more complex approaches that depend on a total ordering distributed consensus ledger. Nevertheless KERI may employ a distributed consensus ledger  when other considerations make it the best choice. The KERI approach to DKMI allows more granular composition. Moreover, because KERI is event streamed it enables DKMI that operates in-stride with data events streaming applications such as web 3.0, IoT, and others where performance and scalability are more important. The core KERI engine is identifier independent. This makes KERI a candidate for a universal portable DKMI. 


--- middle

# Introduction

The major motivation for this work is to provide a secure decentralized foundation of trust for the Internet as a trustable spanning layer. A major flaw in the original design of the Internet Protocol was that it had security layer (i.e. Session or Presentation layers). There was no built-in mechanism for security. Specifically the IP packet header includes a source address field to indicate the IP address of the device that sent the packet. Because the source address may be forged, a recipient may not know if the packet was sent by an imposter. Anyone can forge an IP (Internet Protocol) packet. This means that security mechanisms for the Internet must be overlaid (bolted-on). [KERI] provides such a security overlay.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
