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

  KERI_ID:
    target: https://github.com/WebOfTrust/ietf-keri
    title: IETF KERI (Key Event Receipt Infrastructure) Internet Draft
    date: 2022
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC

  CESR_ID:
    target: https://github.com/WebOfTrust/ietf-cesr
    title: IETF CESR (Composable Event Streaming Representation) Internet Draft
    date: 2022
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC

  SAID_ID:
    target: https://github.com/WebOfTrust/ietf-said
    title: IETF SAID (Self-Addressing IDentifier) Internet Draft
    date: 2022
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022

  OOBI_ID:
    target: https://github.com/WebOfTrust/ietf-oobi
    title: IETF OOBI (Out-Of-Band-Introduction) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022

  DIDK_ID:
    target: https://github.com/WebOfTrust/ietf-did-keri
    title: IETF DID-KERI Internet Draft
    author:
      ins: P. Feairheller
      name: Phil Feairheller
      org: GLEIF


  RFC6901:
    target: https://datatracker.ietf.org/doc/html/rfc6901
    title: JavaScript Object Notation (JSON) Pointer
    date: 2003
    author:
      -
        name: Paul C. Bryan
      -
        name: Kris Zyp
      -
        name: Mark Nottingham

  JSON:
    target: https://www.json.org/json-en.html
    title: JavaScript Object Notation Delimeters

  RFC8259:
    target: https://datatracker.ietf.org/doc/html/rfc8259
    title: JSON (JavaScript Object Notation)

  RFC4627:
    target: https://datatracker.ietf.org/doc/rfc4627/
    title: The application/json Media Type for JavaScript Object Notation (JSON)

  JSch:
    target: https://json-schema.org
    title: JSON Schema

  JSch_202012:
    target: https://json-schema.org/draft/2020-12/release-notes.html
    title: "JSON Schema 2020-12"

  CBOR:
    target: https://en.wikipedia.org/wiki/CBOR
    title: CBOR Mapping Object Codes

  RFC8949:
    target: https://datatracker.ietf.org/doc/rfc8949/
    title: Concise Binary Object Representation (CBOR)
    date: 2020-12-04
    author:
      -
        ins: C. Bormann
        name: Carsten Bormann
      -
        ins: P. Hoffman
        name: Paul Hoffman


  MGPK:
    target: https://github.com/msgpack/msgpack/blob/master/spec.md
    title: Msgpack Mapping Object Codes

  RFC3986:
    target: https://datatracker.ietf.org/doc/html/rfc3986
    title: "Uniform Resource Identifier (URI): Generic Syntax"

  RFC8820:
    target: https://datatracker.ietf.org/doc/html/rfc8820
    title: URI Design and Ownership


informative:

  KERI:
    target: https://arxiv.org/abs/1907.02143
    title: Key Event Receipt Infrastructure (KERI)
    date: 2021
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC

  UIT:
    target: https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/IdentifierTheory_web.pdf
    title: Universay Identifier Theory
    seriesinfo: WhitePaper
    date: 2020
    author:
      ins: S. Smith
      name: Samuel M. Smith

  DAD:
    target: https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/DecentralizedAutonomicData.pdf
    title: "Decentralized Autonomic Data (DAD) and the three R's of Key Management"
    seriesinfo: WhitePaper
    date: 2018
    author:
      ins: S. Smith
      name: Samuel M. Smith

  IDSys:
    target: https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/Identity-System-Essentials.pdf
    title: Identity System Essentials
    seriesinfo: WhitePaper
    date: 2016
    author:
      -
        ins: S. Smith
        name: Samuel M. Smith
      -
        ins: D. Khovratovich
        name: Dmitry Khovratovich

  HCR:
    target: https://en.wikipedia.org/wiki/Collision_resistance
    title: Hash Collision Resistance

  ITPS:
    target: https://en.wikipedia.org/wiki/Information-theoretic_security
    title: Information-Theoretic and Perfect Security

  OTP:
    target: https://en.wikipedia.org/wiki/One-time_pad
    title: One-Time-Pad

  VCphr:
    target: https://www.ciphermachinesandcryptology.com/en/onetimepad.htm
    title: Vernom Cipher (OTP)

  SSplt:
    target: https://www.ciphermachinesandcryptology.com/en/secretsplitting.htm
    title: Secret Splitting

  SShr:
    target: https://en.wikipedia.org/wiki/Secret_sharing
    title: Secret Sharing

  CSPRNG:
    target: https://en.wikipedia.org/wiki/Cryptographically-secure_pseudorandom_number_generator
    title: Cryptographically-secure pseudorandom number generator (CSPRNG)

  IThry:
    target: https://en.wikipedia.org/wiki/Information_theory
    title: Information Theory


  QCHC:
    target: https://cr.yp.to/hash/collisioncost-20090823.pdf
    title: "Cost analysis of hash collisions: Will quantum computers make SHARCS obsolete?"

  EdSC:
    target: https://eprint.iacr.org/2020/823
    title: "The Provable Security of Ed25519: Theory and Practice Report"

  PSEd:
    target: https://ieeexplore.ieee.org/document/9519456?denied=
    title: "The Provable Security of Ed25519: Theory and Practice"
    seriesinfo: "2021 IEEE Symposium on Security and Privacy (SP)"
    date: 2021-05-24
    author:
      -
        ins: J. Brendel
        name: Jacqueline Brendel
      -
        ins: C. Cremers
        name: Cas Cremers
      -
        ins: D. Jackson
        name: Dennis Jackson
      -
        ins: M. Zhao
        name: Mang Zhao

  TMEd:
    target: https://eprint.iacr.org/2020/1244.pdf
    title: Taming the many EdDSAs

  Salt:
    target: https://medium.com/@fridakahsas/salt-nonces-and-ivs-whats-the-difference-d7a44724a447
    title: Salts, Nonces, and Initial Values

  RB:
    target: https://en.wikipedia.org/wiki/Rainbow_table
    title: Rainbow Table

  DRB:
    target: https://www.commonlounge.com/discussion/2ee3f431a19e4deabe4aa30b43710aa7
    title: Dictionary Attacks, Rainbow Table Attacks and how Password Salting defends against them

  BDay:
    target: https://en.wikipedia.org/wiki/Birthday_attack
    title: Birthday Attack

  BDC:
    target: https://auth0.com/blog/birthday-attacks-collisions-and-password-strength/
    title: Birthday Attacks, Collisions, And Password Strength

  DHKE:
    target: https://www.infoworld.com/article/3647751/understand-diffie-hellman-key-exchange.html
    title: "Diffie-Hellman Key Exchange"

  KeyEx:
    target: https://libsodium.gitbook.io/doc/key_exchange
    title: Key Exchange

  Hash:
    target: https://en.wikipedia.org/wiki/Cryptographic_hash_function
    title: Cryptographic Hash Function

  W3C_DID:
    target: https://w3c-ccg.github.io/did-spec/
    title: "W3C Decentralized Identifiers (DIDs) v1.0"

  PKI:
    target: https://en.wikipedia.org/wiki/Public-key_cryptography
    title: Public-key Cryptography

  SCPK:
    target: https://link.springer.com/content/pdf/10.1007%2F3-540-46416-6_42.pdf
    title: Self-certified public keys
    seriesinfo: "EUROCRYPT 1991: Advances in Cryptology, pp. 490-497, 1991"
    author:
      ins: M. Girault
      name: Marc Girault

  SCURL:
    target: https://pdos.csail.mit.edu/~kaminsky/sfs-http.ps
    title: "SFS-HTTP: Securing the Web with Self-Certifying URLs"
    seriesinfo: "Whitepaper, MIT, 1999"
    author:
      -
        ins: M. Kaminsky
        name: M. Kaminsky
      -
        ins: E. Banks
        name: E. Banks

  SFS:
    target: https://pdos.csail.mit.edu/~kaminsky/sfs-http.ps
    title: "Self-certifying File System"
    seriesinfo: “MIT Ph.D. Dissertation"
    date: 2000-06-01
    author:
      ins: D. Mazieres
      name: David Mazieres

  SCPN:
    target: https://dl.acm.org/doi/pdf/10.1145/319195.319213
    title: "Escaping the Evils of Centralized Control with self-certifying pathnames"
    seriesinfo: “MIT Laboratory for Computer Science, 2000"
    author:
      -
        ins: D. Mazieres
        name: David Mazieres
      -
        ins: M. Kaashoek
        name: M. F. Kaashoek

  DNS:
    target: https://en.wikipedia.org/wiki/Domain_Name_System
    title: Domain Name System

  DNSCA:
    target: https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization
    title: DNS Certification Authority Authorization

  CA:
    target: https://en.wikipedia.org/wiki/Certificate_authority
    title: Certificate Authority

  RFC5280:
    target: https://datatracker.ietf.org/doc/html/rfc5280
    title: "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile"

  WOT:
    target: https://en.wikipedia.org/wiki/Web_of_trust
    title: Web of Trust

  CEDS:
    target: "https://resources.infosecinstitute.com/cybercrime-exploits-digital-certificates/#gref"
    title: “How Cybercrime Exploits Digital Certificates”
    seriesinfo: "InfoSecInstitute"
    date: 2014-07-28

  KDDH:
    target: "https://krebsonsecurity.com/2019/02/a-deep-dive-on-the-recent-widespread-dns-hijacking-attacks/"
    title: A Deep Dive on the Recent Widespread DNS Hijacking Attacks
    seriesinfo: "KrebsonSecurity"
    date: 2019-02-19

  DNSH:
    target: "https://arstechnica.com/information-technology/2019/01/a-dns-hijacking-wave-is-targeting-companies-at-an-almost-unprecedented-scale/"
    title: A DNS hijacking wave is targeting companies at an almost unprecedented scale
    seriesinfo: "Ars Technica"
    date: 2019-01-10
    author:
      ins: D. Goodin
      name: Dan Goodin

  SFTCA:
    target: https://pdfs.semanticscholar.org/7876/380d71dd718a22546664b7fcc5b413c1fa49.pdf
    title: "Search for Trust: An Analysis and Comparison of CA System Alternatives and Enhancements"
    seriesinfo: "Dartmouth Computer Science Technical Report TR2012-716, 2012"
    author:
      ins: A. Grant
      name: A. C. Grant

  DNSP:
    target: https://www.thesslstore.com/blog/dns-poisoning-attacks-a-guide-for-website-admins/
    title: "DNS Poisoning Attacks: A Guide for Website Admins"
    seriesinfo: "HashedOut"
    date: 2020/01/21
    author:
      ins: G. Stevens
      name: G. Stevens

  BGPC:
    target: https://petsymposium.org/2017/papers/hotpets/bgp-bogus-tls.pdf
    title: Using BGP to acquire bogus TLS certificates
    seriesinfo: "Workshop on Hot Topics in Privacy Enhancing Technologies, no. HotPETs 2017"
    author:
      ins: "H. Birge-Lee"
      name: "H. Birge-Lee"

  BBGP:
    target: "https://www.usenix.org/conference/usenixsecurity18/presentation/birge-lee"
    title: "Bamboozling certificate authorities with BGP"
    seriesinfo: "vol. 27th USENIX Security Symposium, no. 18, pp. 833-849, 2018"
    author:
      ins: "H. Birge-Lee"
      name: "H. Birge-Lee"


  RFC6962:
    target: https://tools.ietf.org/html/rfc6962
    title: "RFC6962: Certificate Transparency, IETF, 2013"
    date: 2013
    author:
      -
        ins: B. Laurie
        name: B. Laurie
      -
        ins: A. Langley
        name: A. Langley
      -
        ins: E. Kasper
        name: E. Kasper

  CTE:
    target: https://certificate.transparency.dev
    title: Certificate Transparency Ecosystem


  CT:
    target: https://queue.acm.org/detail.cfm?id=2668154
    title: "Certificate Transparency: Public, verifieable, append-only logs"
    seriesinfo: "ACMQueue, vol. Vol 12, Issue 9"
    date: 2014-09-08
    author:
      ins: B. Laurie
      name: B. Laurie

  RT:
    target: https://www.links.org/files/RevocationTransparency.pdf
    title: Revocation Transparency

  VDS:
    target: https://github.com/google/trillian/blob/master/docs/papers/VerifiableDataStructures.pdf
    title: Verifiable Data Structures
    seriesinfo: "WhitePaper"
    date:  2015-11-01

  ESMT:
    target: https://eprint.iacr.org/2016/683.pdf
    title: Efficient sparse merkle trees
    seriesinfo: "Nordic Conference on Secure IT Systems, pp. 199-215, 2016"


--- abstract

An identity system-based secure overlay for the Internet is presented. This is based on a Key Event Receipt Infrastructure (KERI) or the KERI protocol {{KERI}}{{KERI_ID}} . This includes a primary root-of-trust in self-certifying identifiers (SCIDs) {{UIT}}{{SCPK}}{{SFS}}{{SCPN}}{{SCURL}}. It presents a formalism for Autonomic Identifiers (AIDs) and Autonomic Namespaces (ANs). They are part of an Autonomic Identity System (AIS). This system uses the design principle of minimally sufficient means to provide a candidate trust spanning layer for the internet. Associated with this system is a decentralized key management infrastructure (DKMI). The primary root-of-trust are self-certifying identifiers that are strongly bound at issuance to a cryptographic signing (public, private) key-pair. These are self-contained until/unless control needs to be transferred to a new key-pair. In that event an append-only chained key-event log of signed transfer statements provides end verifiable control provenance. This makes intervening operational infrastructure replaceable because the event logs may be served up by any infrastructure including ambient infrastructure. End verifiable logs on ambient infrastructure enable ambient verifiability (verifiable by anyone, anywhere, at anytime).
The primary key management operation is key rotation (transference) via a novel key pre-rotation scheme {{DAD}}{{KERI}}. Two primary trust modalities motivated the design, these are a direct (one-to-one) mode and an indirect (one-to-any) mode. The indirect mode depends on witnessed key event receipt logs (KERL) as a secondary root-of-trust for validating events. This gives rise to the acronym KERI for key event receipt infrastructure. In the direct mode, the identity controller establishes control via verified signatures of the controlling key-pair. The indirect mode extends that trust basis with witnessed key event receipt logs (KERL) for validating events. The security and accountability guarantees of indirect mode are provided by KA2CE or KERI’s Agreement Algorithm for Control Establishment among a set of witnesses.
The KA2CE approach may be much more performant and scalable than more complex approaches that depend on a total ordering distributed consensus ledger. Nevertheless, KERI may employ a distributed consensus ledger when other considerations make it the best choice. The KERI approach to DKMI allows for more granular composition. Moreover, because KERI is event streamed it enables DKMI that operates in-stride with data events streaming applications such as web 3.0, IoT, and others where performance and scalability are more important. The core KERI engine is identifier namespace independent. This makes KERI a candidate for a universal portable DKMI {{KERI}}{{KERI_ID}}{{UIT}}.




--- middle

# Introduction

The main motivation for this work is to provide a secure decentralized foundation of attributional trust for the Internet as a trustable spanning layer in the form of an identifier system security overlay. This identifier system security overlay provides verifiable authorship (authenticity) of any message or data item via secure (cryptographically verifiable) attribution to a *cryptonymous (cryptographic strength pseudonymous)* *self-certifying identifier (SCID)* {{KERI}}{{UIT}}{{SCPK}}{{SFS}}{{SCPN}}{{SCURL}}{{PKI}}.

A major flaw in the original design of the Internet Protocol was that it has no security layer(s) (i.e. Session or Presentation layers) to provide interoperable verifiable authenticity. There was no built-in mechanism for secure attribution to the source of a packet. Specifically, the IP packet header includes a source address field that indicates the IP address of the device that sent the packet. Anyone (including any intermediary) can forge an IP (Internet Protocol) packet. Because the source address of such a packet can be undetectably forged, a recipient may not be able to ascertain when or if the packet was sent by an imposter.  This means that secure attribution mechanisms for the Internet must be overlaid (bolted-on). KERI provides such a security overlay. We describe it as an identifier system security overlay. The KERI identifier system overlay leverages the properties of cryptonymous *self-certifying identifiers* (SCIDs) which are based on asymmetric public-key cryptography (PKI) to provide end-verifiable secure attribution of any message or data item without needing to trust in any intermediary {{PKI}}{{KERI}}{{UIT}}{{SCPK}}{{SFS}}{{SCPN}}{{SCURL}}{{PKI}}.



## Key Pre-Rotation

An important innovation of KERI is that it solves the key rotation problem of PKI and simple self-certifying identifiers via a novel but elegant mechanism we call key pre-rotation {{DAD}}{{KERI}}. This pre-rotation mechanism enables an entity to persistently maintain or regain control over an identifier in spite of the weakening over time or even the compromise of the current set of signing key pairs due to exposure. This control is re-established by rotating to a one-time use set of unexposed rotation key pairs that then become the current signing key pairs. Each rotation cryptographically commits to a new set of rotation keys without exposing them. Because the pre-rotated key pairs need never be exposed prior to their one-time use, their attack surface may be optimally minimized. The current key state is maintained via an append-only verifiable data structure we call a key event log (KEL). This gives rise to a new class of persistent decentralized identifiers which we call ***autonomic identifiers*** (AIDs). Autonomic means self-governing, self-regulating, or self-managing and is evocative of the self-certifying, self-relying, self-managing properties of this class of identifier.

## Identifier-System Security-Overlay

The function of the identifier-system security-overlay is to establish the authenticity (or authorship) of the message payload in an IP Packet by verifiably attributing it to a cryptonymous identifier via an attached set of one or more asymmetric key-pair-based non-repudiable digital signatures. The current valid set of associated asymmetric key-pair(s) is proven via a verifiable data structure called a key event log (KEL) {{KERI}}{{VDS}}{{ESMT}}{{RT}}. The identifier system provides a mapping between the identifier and the key-pair(s) that control the identifier, namely, the public key(s) from those key-pairs. The private key(s) is secret and is not shared.

An authenticatable (verifiable) internet message (packet) or data item includes the identifier and data in its payload. Attached to the payload is a digital signature(s) made with the private key(s) from the controlling key-pair(s). Given the identifier in a message, any verifier of a message (data item) can use the identifier system mapping to look up the public key(s) belonging to the controlling key-pair(s). The verifier can then verify the attached signature(s) using that public key(s). Because the payload includes the identifier, the signature makes a non-repudiable cryptographic commitment to both the source identifier and the data in the payload.

### Flaws

There are two major flaws in many other PKI-based identifier system security overlays (including the Internet's DNS/CA system) {{PKI}}{{DNS}}{{DNSCA}}{{CA}}{{RFC5280}}.

The first major flaw is that the mapping between the identifier (domain name) and the controlling key-pair(s) is asserted by a trusted entity e.g. certificate authority (CA) via a certificate. Because the mapping is merely asserted, a verifier can not cryptographically verify the mapping between the identifier and the controlling key-pair(s) but must trust the operational processes of the trusted entity (CA) who issued and signed the certificate. Important to note is that signature on the certificate is NOT made with the controlling key pairs of the identifier but made with key pairs controlled by the issuer (CA). The fact that the certificate is signed by the CA does not make the mapping itself verifiable merely that the assertion was made by the CA. The certificate addresses the authenticity of the mapping but not the veracity of the mapping. As is well known, a successful attack upon those operational processes may fool the verifier into trusting an invalid mapping i.e. the certificate {{CEDS}}{{KDDH}}{{DNSH}}{{SFTCA}}{{DNSP}}{{BGPC}}{{BBGP}}.

The second major flaw is that when rotating the valid signing keys there is no cryptographically verifiable way to link the new (rotated in) controlling/signing key(s) to the prior (rotated out) controlling/signing key(s). Key rotation is merely implicitly asserted by a trusted entity (CA) by issuing a new certificate with new controlling/signing keys. Key rotation is necessary because over time the controlling key-pair(s) of an identifier becomes weak due to exposure when used to sign messages and must be replaced. Essentially, rotation by assertion with implicit revocation and replacement is essentially the same as starting over by creating a brand new independent mapping between a given identifier and a controlling key-pair(s). This start-over (independent) style of key rotation may well be one of the main reasons that PGP's web-of-trust failed {{WOT}}. Independence between rotation assertions fosters ambiguity as to the actual valid mapping between the identifier and its controlling key-pair(s) at any point in time. We call the state of the controlling keys for an identifier at any time the key state. Tracking key-state over time is essential to preventing this ambiguity. Without this tracking, the detection of potential ambiguity requires yet another bolt-on security overlay such as the certificate transparency system {{CTE}}{{CT}}{{RFC6962}}{{RT}}{{VDS}}{{ESMT}}.

The KERI protocol fixes both of these flaws using a combination of ***autonomic identifiers***, a novel key ***pre-rotation*** scheme, a ***verifiable data structure*** (VDS) called a KEL as proof of key-state, and ***duplicity-evident*** mechanisms for evaluating and reconciling key state {{KERI}}.

### Binding

Any identifier-system security-overlay binds together identifiers, asymmetric key-pairs, and controllers. By ***identifier*** we mean some string of characters. By ***key-pairs*** we mean a set of asymmetric (public, private) cryptographic key pairs used to create and verify non-repudiable digital signatures. By ***controller*** we mean the entity or entities that each control a private key from the given set of ***key-pairs***.


The following diagram shows the basic concept.




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
