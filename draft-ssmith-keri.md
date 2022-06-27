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

  KERI-ID:
    target: https://github.com/WebOfTrust/ietf-keri
    title: IETF KERI (Key Event Receipt Infrastructure) Internet Draft
    date: 2022
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC

  CESR-ID:
    target: https://github.com/WebOfTrust/ietf-cesr
    title: IETF CESR (Composable Event Streaming Representation) Internet Draft
    date: 2022
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC

  SAID-ID:
    target: https://github.com/WebOfTrust/ietf-said
    title: IETF SAID (Self-Addressing IDentifier) Internet Draft
    date: 2022
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022

  OOBI-ID:
    target: https://github.com/WebOfTrust/ietf-oobi
    title: IETF OOBI (Out-Of-Band-Introduction) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022

  DIDK-ID:
    target: https://github.com/WebOfTrust/ietf-did-keri
    title: IETF DID-KERI Internet Draft
    author:
      ins: P. Feairheller
      name: Phil Feairheller
      org: GLEIF

  RFC8259: JSON

  JSOND:
    target: https://www.json.org/json-en.html
    title: JavaScript Object Notation Delimiters

  RFC8949: CBOR

  CBORC:
    target: https://en.wikipedia.org/wiki/CBOR
    title: CBOR Mapping Object Codes

  MGPK:
    target: https://github.com/msgpack/msgpack/blob/master/spec.md
    title: Msgpack Mapping Object Codes


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

  RFC4648: Base64

  RFC0020: ASCII

  RFC3986: URI

  RFC8820: URIDesign

  RFC4627: JSONMIME

  JSch:
    target: https://json-schema.org
    title: JSON Schema

  JSch_202012:
    target: https://json-schema.org/draft/2020-12/release-notes.html
    title: "JSON Schema 2020-12"

  RFC6901: JSONPTR

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

  TMCrypto:
    target: https://eprint.iacr.org/2019/1492.pdf
    title: “Too Much Crypto”
    date: 2021-05-24
    author:
        ins: J. Aumasson
        name: Jean-Philippe Aumasson

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

  Stretch:
    target: https://en.wikipedia.org/wiki/Key_stretching
    title: Key stretching

  HDKC:
    target: https://github.com/WebOfTrustInfo/rwot1-sf/blob/master/topics-and-advance-readings/hierarchical-deterministic-keys--bip32-and-beyond.md
    title: "Hierarchical Deterministic Keys: BIP32 & Beyond"
    author:
      -
        ins: C. Allen
        name: Christopher Allen
      -
        ins: S. Applecline
        name: Shannon Applecline

  OWF:
    target: https://en.wikipedia.org/wiki/One-way_function
    title: One-way_function

  COWF:
    target: http://www.crypto-it.net/eng/theory/one-way-function.html
    title: One-way Function
    seriesinfo: Crypto-IT

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

  RFC0791: IP

  RFC0799: IND

  DNS:
    target: https://en.wikipedia.org/wiki/Domain_Name_System
    title: Domain Name System

  CAA:
    target: https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization
    title: DNS Certification Authority Authorization

  CA:
    target: https://en.wikipedia.org/wiki/Certificate_authority
    title: Certificate Authority

  RFC5280: ICRL

  CRL:
     target: https://en.wikipedia.org/wiki/Certificate_revocation_list
     title: Certificate Revocation List

  RFC6960: OCSP

  OCSPW:
     target: https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol
     title: Online Certificate Status Protocol

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


  RFC6962: CT


  CTE:
    target: https://certificate.transparency.dev
    title: Certificate Transparency Ecosystem


  CTAOL:
    target: https://queue.acm.org/detail.cfm?id=2668154
    title: "Certificate Transparency: Public, verifiable, append-only logs"
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

  BLAKE3:
    target: ttps://github.com/BLAKE3-team/BLAKE3
    title: BLAKE3

  BLAKE3Spec:
    target: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
    title: BLAKE3 one function, fast everywhere

  BLAKE3Hash:
    target: https://www.infoq.com/news/2020/01/blake3-fast-crypto-hash/
    title: “BLAKE3 Is an Extremely Fast, Parallel Cryptographic Hash”
    seriesinfo: InfoQ
    date: 2020-01-12


--- abstract

An identity system-based secure overlay for the Internet is presented. This is based on a Key Event Receipt Infrastructure (KERI) or the KERI protocol {{KERI}}{{KERI-ID}}{{RFC0791}}. This includes a primary root-of-trust in self-certifying identifiers (SCIDs) {{UIT}}{{SCPK}}{{SFS}}{{SCPN}}{{SCURL}}. It presents a formalism for Autonomic Identifiers (AIDs) and Autonomic Namespaces (ANs). They are part of an Autonomic Identity System (AIS). This system uses the design principle of minimally sufficient means to provide a candidate trust spanning layer for the internet. Associated with this system is a decentralized key management infrastructure (DKMI). The primary root-of-trust are self-certifying identifiers that are strongly bound at issuance to a cryptographic signing (public, private) keypair. These are self-contained until/unless control needs to be transferred to a new keypair. In that event, an append-only chained key-event log of signed transfer statements provides end verifiable control provenance. This makes intervening operational infrastructure replaceable because the event logs may be served up by any infrastructure including ambient infrastructure. End verifiable logs on ambient infrastructure enable ambient verifiability (verifiable by anyone, anywhere, at any time).
The primary key management operation is key rotation (transference) via a novel key pre-rotation scheme {{DAD}}{{KERI}}. Two primary trust modalities motivated the design, these are a direct (one-to-one) mode and an indirect (one-to-any) mode. The indirect mode depends on witnessed key event receipt logs (KERL) as a secondary root-of-trust for validating events. This gives rise to the acronym KERI for key event receipt infrastructure. In the direct mode, the identity controller establishes control via verified signatures of the controlling keypair. The indirect mode extends that trust basis with witnessed key event receipt logs (KERL) for validating events. The security and accountability guarantees of indirect mode are provided by KA2CE or KERI’s Agreement Algorithm for Control Establishment among a set of witnesses.
The KA2CE approach may be much more performant and scalable than more complex approaches that depend on a total ordering distributed consensus ledger. Nevertheless, KERI may employ a distributed consensus ledger when other considerations make it the best choice. The KERI approach to DKMI allows for more granular composition. Moreover, because KERI is event streamed it enables DKMI that operates in-stride with data events streaming applications such as web 3.0, IoT, and others where performance and scalability are more important. The core KERI engine is identifier namespace independent. This makes KERI a candidate for a universal portable DKMI {{KERI}}{{KERI-ID}}{{UIT}}.




--- middle

# Introduction

The main motivation for this work is to provide a secure decentralized foundation of attributional trust for the Internet as a trustable spanning layer in the form of an identifier system security overlay. This identifier system security overlay provides verifiable authorship (authenticity) of any message or data item via secure (cryptographically verifiable) attribution to a *cryptonymous (cryptographic strength pseudonymous)* *self-certifying identifier (SCID)* {{KERI}}{{UIT}}{{SCPK}}{{SFS}}{{SCPN}}{{SCURL}}{{PKI}}.

A major flaw in the original design of the Internet Protocol was that it has no security layer(s) (i.e. Session or Presentation layers) to provide interoperable verifiable authenticity {{RFC0791}}. There was no built-in mechanism for secure attribution to the source of a packet. Specifically, the IP packet header includes a source address field that indicates the IP address of the device that sent the packet. Anyone (including any intermediary) can forge an IP (Internet Protocol) packet. Because the source address of such a packet can be undetectably forged, a recipient may not be able to ascertain when or if the packet was sent by an imposter.  This means that secure attribution mechanisms for the Internet must be overlaid (bolted-on). KERI provides such a security overlay. We describe it as an identifier system security overlay.

## Self-Certifying IDentifier (SCID)

The KERI identifier system overlay leverages the properties of cryptonymous ***self-certifying identifiers*** (SCIDs) which are based on asymmetric public-key cryptography (PKI) to provide end-verifiable secure attribution of any message or data item without needing to trust in any intermediary {{PKI}}{{KERI}}{{UIT}}{{SCPK}}{{SFS}}{{SCPN}}{{SCURL}}. A self-certifying identifier (SCID) is uniquely cryptographically derived from the public key of an asymmetric keypair, `(public, private)`. It is self-certifying in the sense that does not rely on a trusted entity. Any non-repudiable signature made with the private key may be verified by extracting the public key from either the identifier itself or incepting information uniquely associated with the cryptographic derivation process for the identifier. In a basic SCID, the mapping between an identifier and its controlling public key is self-contained in the identifier itself. A basic SCID is *ephemeral* i.e. it does not support rotation of its keypairs in the event of key weakness or compromise and therefore must be abandoned once the controlling private key becomes weakened or compromised from exposure. The class of identifiers that generalize SCIDs with enhanced properties such as persistence is called *autonomic identifiers* (AIDs).

## Autonomic IDentifier (AID)

A Key Event Log (KEL) gives rise to an enhanced class of SCIDs that are persistent, not ephemeral, because their keys may be refreshed or updated via rotation allowing secure control over the identifier in spite of key weakness or even compromise.
This family of generalized enhanced SCIDs we call ***autonomic identifiers*** (AIDs). *Autonomic* means self-governing, self-regulating, or self-managing and is evocative of the self-certifying, self-managing properties of this class of identifier.

## Key Pre-rotation Basics

An important innovation of KERI is that it solves the key rotation problem of PKI (including that of simple self-certifying identifiers) via a novel but elegant mechanism we call ***key pre-rotation*** {{DAD}}{{KERI}}. This *pre-rotation* mechanism enables an entity to persistently maintain or regain control over an identifier in spite of the exposure-related weakening over time or even compromise of the current set of controlling (signing) keypairs. With key pre-rotation, control over the identifier can be re-established by rotating to a one-time use set of unexposed but pre-committed rotation keypairs that then become the current signing keypairs. Each rotation in turn cryptographically commits to a new set of rotation keys but without exposing them. Because the pre-rotated keypairs need never be exposed prior to their one-time use, their attack surface may be optimally minimized. The current key-state is maintained via an append-only ***verifiable data structure*** we call a ***key event log*** (KEL).


## Cryptographic Primitives

### CESR

A ***cryptographic primitive ***is a serialization of a value associated with a cryptographic operation including but not limited to a digest (hash), a salt, a seed, a private key, a public key, or a signature. All cryptographic primitives in KERI MUST be expressed using the CESR (Compact Event Streaming Representation) protocol {{CESR-ID}}.  CESR supports round trip lossless conversion between its text, binary, and raw domain representations and lossless composability between its text and binary domain representations. Composability is ensured between any concatenated group of text primitives and the binary equivalent of that group because all CESR primitives are aligned on 24-bit boundaries. Both the text and binary domain representations are serializations suitable for transmission over the wire. The text domain representation is also suitable to be embedded as a string value of a field or array element as part of a field map serialization such as JSON, CBOR, or MsgPack {{RFC8259}}{{JSOND}}{{RFC8949}}{{CBORC}}{{MGPK}}. The text domain uses the set of characters from the URL-safe variant of Base64 which in turn is a subset of the ASCII character set {{RFC4648}}{{RFC0020}}. For the sake of readability, all examples in this specification will be expressed in CESR's text-domain.

### Qualified Cryptographic Primitive

When *qualified*, a cryptographic primitive includes a prepended derivation code (as a proem) that indicates the cryptographic algorithm or suite used for that derivation. This simplifies and compactifies the essential information needed to use that cryptographic primitive. All cryptographic primitives expressed in either text or binary CESR are *qualified* by definition. Qualification is an essential property of CESR {{CESR-ID}}. The CESR protocol supports several different types of encoding tables for different types of derivation codes. These tables include very compact codes. For example, a 256-bit (32-byte) digest using the BLAKE3 digest algorithm, i.e. Blake3-256, when expressed in text-domain CESR is 44 Base64 characters long and begins with the one character derivation code `E`, such as, `EL1L56LyoKrIofnn0oPChS4EyzMHEEk75INJohDS_Bug` {{BLAKE3}}{{BLAKE3Spec}}{{BLAKE3Hash}}. The equivalent *qualified* binary domain representation is 33 bytes long.
Unless otherwise indicated, all cryptographic primitives in this specification will appear as *qualified* primitives using text-domain CESR.

## Identifier System Security Overlay

The function of KERI's identifier-system security overlay is to establish the authenticity (or authorship) of the message payload in an IP Packet by verifiably attributing it to a cryptonymous self-certifying identifier (AID) via an attached set of one or more asymmetric key-pair-based non-repudiable digital signatures. The current valid set of associated asymmetric keypair(s) is proven via a verifiable data structure called a ***key event log*** (KEL) {{KERI}}{{VDS}}{{ESMT}}{{RT}}. The identifier system provides a mapping between the identifier and the keypair(s) that control the identifier, namely, the public key(s) from those keypairs. The private key(s) is secret and is not shared.

An authenticatable (verifiable) internet message (packet) or data item includes the identifier and data in its payload. Attached to the payload is a digital signature(s) made with the private key(s) from the controlling keypair(s). Given the identifier in a message, any verifier of a message (data item) can use the identifier system mapping to look up the public key(s) belonging to the controlling key-pair(s). The verifier can then verify the attached signature(s) using that public key(s). Because the payload includes the identifier, the signature makes a non-repudiable cryptographic commitment to both the source identifier and the data in the payload.

### Security Overlay Flaws

There are two major flaws in conventional PKI-based identifier system security overlays (including the Internet's DNS/CA system) {{PKI}}{{DNS}}{{RFC0799}}{{CAA}}{{CA}}{{RFC5280}}.

The *first major flaw** is that the mapping between the identifier (domain name) and the controlling key-pair(s) is merely asserted by a trusted entity e.g. certificate authority (CA) via a certificate. Because the mapping is merely asserted, a verifier can not cryptographically verify the mapping between the identifier and the controlling key-pair(s) but must trust the operational processes of the trusted entity making that assertion, i.e. the CA who issued and signed the certificate. As is well known, a successful attack upon those operational processes may fool a verifier into trusting an invalid mapping i.e. the certificate is issued to the wrong key-pair(s) albeit with a verifiable signature from a valid certificate authority. {{CEDS}}{{KDDH}}{{DNSH}}{{SFTCA}}{{DNSP}}{{BGPC}}{{BBGP}}. Noteworthy is that the signature on the certificate is NOT made with the controlling keypairs of the identifier but made with keypairs controlled by the issuer i.e. the CA. The fact that the certificate is signed by the CA means that the mapping itself is not verifiable but merely that the CA asserted the mapping between key-pair(s) and identifier. The certificate merely provides evidence of the authenticity of the assignment of the mapping but not evidence of the veracity of the mapping.

The *second major flaw* is that when rotating the valid signing keys there is no cryptographically verifiable way to link the new (rotated in) controlling/signing key(s) to the prior (rotated out) controlling/signing key(s). Key rotation is merely implicitly asserted by a trusted entity (CA) by issuing a new certificate with new controlling/signing keys.  Key rotation is necessary because over time the controlling key-pair(s) of an identifier becomes weak due to exposure when used to sign messages and must be replaced. An explicit rotation mechanism first revokes the old keys and then replaces them with new keys. Even a certificate revocation list (CRL) as per RFC5280, with an online status protocol (OCSP) registration as per RFC6960, does not provide a cryptographically verifiable connection between the old and new keys, it is merely asserted {{RFC5280}}{{RFC6960}}{{OCSPW}}. The lack of a single universal CRL or registry means that multiple potential replacements may be valid. From a cryptographic verifiability perspective, rotation by assertion with a new certificate that either implicitly or explicitly provides revocation and replacement is essentially the same as starting over by creating a brand new independent mapping between a given identifier and the controlling key-pair(s). This start-over style of key rotation may well be one of the main reasons that PGP's web-of-trust failed {{WOT}}. Without a universally verifiable revocation mechanism, then any rotation (revocation and replacement) assertions either explicit or implicit are mutually independent of each other. This lack of universal cryptographic verifiability of a rotation fosters ambiguity at any point in time as to the actual valid mapping between the identifier and its controlling keypair(s). In other words, for a given identifier, any or all assertions made by some set of CAs may be potentially valid.

We call the state of the controlling keys for an identifier at any time the key state. Cryptographic verifiability of the key state over time is essential to remove this ambiguity. Without this verifiability, the detection of potential ambiguity requires yet another bolt-on security overlay such as the certificate transparency system {{CTE}}{{CTAOL}}{{RFC6962}}{{RT}}{{VDS}}{{ESMT}}.

The KERI protocol fixes both of these flaws using a combination of ***autonomic identifiers***, ***key pre-rotation***, a ***verifiable data structure*** (VDS) called a KEL as verifiable proof of key-state, and ***duplicity-evident*** mechanisms for evaluating and reconciling key state by validators {{KERI}}. Unlike certificate transparency, KERI enables the detection of duplicity in the key state via non-repudiable cryptographic proofs of duplicity not merely the detection of inconsistency in the key state that may or may not be duplicitous {{KERI}}{{CTAOL}}.


### Triad Bindings

In simple form an identifier-system security-overlay binds together a triad consisting of the ***identifier***, ***keypairs***, and ***controllers***. By ***identifier*** we mean some string of characters. By ***keypairs*** we mean a set of asymmetric (public, private) cryptographic keypairs used to create and verify non-repudiable digital signatures. By ***controllers*** we mean the set of entities whose members each control a private key from the given set of ***keypairs***. When those bindings are strong then the overlay is highly *invulnerable* to attack.  In contrast, when those bindings are weak then the overlay is highly *vulnerable* to attack. The bindings for a given identifier form a *triad* that binds together the set of *controllers*, the set of *key-pairs*, and the *identifier*. To reiterate, the set of controllers is bound to the set of keypairs, the set of keypairs is bound to the identifier, and the identifier is bound to the set of controllers. This binding triad can be diagrammed as a triangle where the sides are the bindings and the vertices are the *identifier*, the set of *controllers*, and the set of *keypairs*.

With KERI all the bindings of the triad are strong because they are cryptographically verifiable with a minimum cryptographic strength or level of approximately 128 bits. See the Appendix on cryptographic strength for more detail.

The bound triad is created as follows\:

* Each controller in the set of controllers creates an asymmetric `(pubic, private)` keypair. The public key is derived from the private key or seed using a one-way derivation that MUST have a minimum cryptographic strength of approximately 128 bits {{OWF}}{{COWF}}. Depending on the crypto-suite used to derive a keypair the private key or seed may itself have a length larger than 128 bits. A controller may use a cryptographic strength pseudo-random number generator (CSPRNG) {{CSPRNG}} to create the private key or seed material. Because the private key material must be kept secret, typically in a secure data store, the management of those secrets may be an important consideration. One approach to minimize the size of secrets is to create private keys or seeds from a secret salt. The salt MUST have an entropy of approximately 128 bits. The salt may then be stretched to meet the length requirements for the crypto suite's private key size {{Salt}}{{Stretch}}. In addition, a hierarchical deterministic derivation function may be used to further minimize storage requirements by leveraging a single salt for a set or sequence of private keys {{HDKC}}. Because each controller is the only entity in control (custody) of the private key, and the public key is universally uniquely derived from the private key using a cryptographic strength one-way function, then the binding between each controller and their key-pair is as strong as the ability of the controller to keep that key private {{OWF}}{{COWF}}. The degree of protection is up to each controller to determine. For example, a controller could choose to store their private key in a safe, at the bottom of a coal mine, air-gapped from any network, with an ex-special forces team of guards. Or the controller could choose to store it in an encrypted data store (key chain) on a secure boot mobile device with a biometric lock or simply write it on a piece of paper and store it in a safe place. The important point is that the strength of the binding between controller and key-pair and does not need to be dependent on any trusted entity.

* The identifier is universally uniquely derived from the set of public keys using a one-way derivation function {{OWF}}{{COWF}}. It is therefore an AID (qualified SCID). Associated with each identifier (AID) is incepting information that MUST include a list of the set of *qualified* public keys from the controlling key-pairs. In the usual case, the identifier is a *qualified* cryptographic digest of the serialization of all the incepting information for the identifier. Any change to even one bit of the incepting information changes the digest and hence changes the derived identifier. This includes any change to any one of the qualified public keys including its qualifying derivation code. To clarify, a *qualified* digest as identifier includes a derivation code as proem that indicates the cryptographic algorithm used for the digest. Thus a different digest algorithm results in a different identifier. In this usual case, the identifier is strongly cryptographically bound to not only the public keys but also any other incepting information from which the digest was generated.

A special case may arise when the set of public keys has only one member, i.e. there is only one controlling key-pair. In this case, the controller of the identifier may choose to use only the *qualified* public key as the identifier instead of a *qualified* digest of the incepting information. In this case, the identifier is still strongly bound to the public key but is not so strongly bound to any other incepting information.  A variant of this single key-pair special case is an identifier that can not be rotated. Another way of describing an identifier that cannot be rotated is that it is a *non-transferable* identifier because control over the identifier cannot be transferred to a different set of controlling key-pairs. Whereas a rotatable key-pair is *transferable* because control may be transfered via rotation to a new set of key-pairs. Essentially, when non-transferable, the identifier's lifespan is *ephemeral*, not *persistent*, because any weakening or compromise of the controlling key-pair means that the identifier must be abandoned. Nonetheless, there are important use cases for an *ephemeral* self-certifying identifier. In all cases, the derivation code in the identifier indicates the type of identifier, whether it be a digest of the incepting information (multiple or single key-pair) or a single member special case derived from only the public key (both ephemeral or persistent).

* Each controller in a set of controllers is may prove its contribution to the control over the identifier in either an interactive or non-interactive fashion. One form of interactive proof is to satisfy a challenge of that control. The challenger creates a unique challenge message. The controller responds by non-repudiably signing that challenge with the private key from the key-pair under its control. The challenger can then cryptographically verify the signature using the public key from the controller's key-pair. One form of non-interactive proof is to periodically contribute to a monotonically increasing sequence of non-repudiably signed updates of some data item. Each update includes a monotonically increasing sequence number or date-time stamp. Any observer can then cryptographically verify the signature using the public key from the controller's key-pair and verify that the update was made by the controller.  In general, only members of the set of controllers can create verifiable non-repudiable signatures using their key-pairs. Consequently, the identifier is strongly bound to the set of controllers via provable control over the key-pairs.

*** Tetrad Bindings

At inception, the triad of identifier, key-pairs, and controllers are strongly bound together. But in order for those bindings to persist after a key rotation, another mechanism is required. That mechanism is a verifiable data structure called a *key event log* (KEL) {{KERI}}{{VDS}}.  The KEL is not necessary for identifiers that are non-transferable and do not need to persist control via key rotation in spite of key weakness or compromise. To reiterate, transferable (persistent) identifiers each need a KEL, non-transferable (ephemeral) identifiers do not.

For persistent (transferable) identifiers, this additional mechanism may be bound to the triad to form a tetrad consisting of the KEL, the identifier, the set of key-pairs, and the set of controllers. The first entry in the KEL is called the *inception event* which is a serialization of the incepting information associated with the identifier mentioned previously.

The *inception event* MUST include the list of controlling public keys. It MUST also include a signature threshold and MUST be signed by a set of private keys from the controlling key-pairs that satisfy that threshold. Additionally, for transferability (persistence across rotation) the *inception event* MUST also include a list of digests of the set of pre-rotated public keys and a pre-rotated signature threshold that will become the controlling (signing) set of key-pairs and threshold after a rotation.  A non-transferable identifier MAY have a trivial KEL that only includes an *inception event* but with a null set (empty list) of pre-rotated public keys.

A rotation is performed by appending to the KEL a *rotation event*. A *rotation event* MUST include a list of the set of pre-rotated public keys (not their digests) thereby exposing them and MUST be signed by a set of private keys from these newly exposed newly controlling but pre-rotated key-pairs that satisfy the pre-rotated threshold. The rotation event MUST also include a list of the digests of a new set of pre-rotated keys as well as the signature threshold for the set of pre-rotated key-pairs. At any point in time the transferability of an identifier can be removed via a *rotation event* that rotates to a null set (empty list) of pre-rotated public keys.

Each event in a KEL MUST include an integer sequence number that is one greater than the previous event. Each event after the inception event MUST also include a cryptographic digest of the previous event. This digest means that a given event is cryptographically bound to the previous event in the sequence. The list of digests or pre-rotated keys in the inception event cryptographically binds the inception event to a subsequent rotation event. Essentially making a forward commitment that forward chains together the events. The only valid rotation event that may follow the inception event must include the pre-rotated keys. But only the controller who created those keys and created the digests may verifiably expose them. Each rotation event in turn makes a forward commitment (chain) to the following rotation event via its list of pre-rotated key digests.   This makes the KEL a doubly (backward and forward) hash (digest) chained non-repudiably signed append-only verifiable data structure.

Because the signatures on each event are non-repudiable, the existence of an alternate but verifiable KEL for an identifier is provable evidence of duplicity. In KERI, there may be at most one valid KEL for any identifier or none at all. Any validator of a KEL may enforce this one valid KEL rule before relying on the KEL as proof of the current key state for the identifier. This protects the validator. Any unreconcilable evidence of duplicity means the validator does not trust (rely on) any KEL to provide the key state for the identifier. Rules for handling reconciliable duplicity will be discussed later.  From a validator's perspective, either there is one-and-only-one valid KEL or none at all. This protects the validator. This policy removes any potential ambiguity about key state.  The combination of a verifiable KEL made from non-repudiably signed backward and forward hash chained events together with the only-one-valid KEL rule strongly binds the identifier to its current key-state as given by that one valid KEL or not at all. This in turn binds the identifier to the controllers of the current key-pairs given by the KEL thus completing the tetrad.

At inception, the KEL may be even more strongly bound to its tetrad by deriving the identifier from a digest of the *inception event*. Thereby even one change in not only the original controlling keys pairs but also the pre-rotated keypairs or any other incepting information included in the *inception event* will result in a different identifier.

The essense of the KERI protocol is a strongly bound tetrad of identifier, key-pairs, controllers, and key event log that forms the basis of its identifier system security overlay. The KERI protocol introduces the concept of duplicity evident programming via duplicity evident verifiable data structures. The full detailed exposition of the protocol is provided in the following sections.

# Basic Terminology

Several new terms were introduced above. These along with other terms helpful to describing KERI are defined below.

Primitive
: A serialization of a unitary value. A *cryptographic primitive* is the serialization of a value associated with a cryptographic operation including but not limited to a digest (hash), a salt, a seed, a private key, a public key, or a signature. All *primitives* in KERI MUST be expressed in CESR (Compact Event Streaming Representation) {{CESR-ID}}.

Qualified
: When *qualified*, a *cryptographic primitive* includes a prepended derivation code (as a proem) that indicates the cryptographic algorithm or suite used for that derivation. This simplifies and compactifies the essential information needed to use that *cryptographic primitive*. All *cryptographic primitives* expressed in either text or binary CESR are *qualified* by definition {{CESR-ID}}. Qualification is an essential property of CESR {{CESR-ID}}.

Cryptonym
: A cryptographic pseudonymous identifier represented by a string of characters derived from a random or pseudo-random secret seed or salt via a one-way cryptogrphic function with a sufficiently high degree of cryptographic strength (e.g. 128 bits, see appendix on cryptographic strength) {{OWF}}{{COWF}}{{TMCrypto}}{{QCHC}}. A *cryptonym* is a type of *primitive*. Due the enctropy in its derivation, a *cryptonym* is a universally unique identifier and only the controller of the secret salt or seed from which the *cryptonym* is derived may prove control over the *cryptonym*. Therefore the derivation function MUST be associated with the *cryptonym* and MAY be encoded as part of the *cryptonym* itself.

SCID
: Self-Certifying IDentifier.  A self-certifying identifier (SCID) is a type of cryptonym that is uniquely cryptographically derived from the public key of an asymmetric non-repudiable signing key-pair, `(public, private)`. It is self-certifying or more precisely self-authenticating because it does not rely on a trusted entity. The authenticity of a non-repudiable signature made with the private key may be verified by extracting the public key from either the identifier itself or incepting information uniquely associated with the cryptographic derivation process for the identifier. In a basic SCID, the mapping between an identifier and its controlling public key is self-contained in the identifier itself. A basic SCID is *ephemeral* i.e. it does not support rotation of its keypairs in the event of key weakness or compromise and therefore must be abandoned once the controlling private key becomes weakened or compromised from exposure {{PKI}}{{KERI}}{{UIT}}{{SCPK}}{{SFS}}{{SCPN}}{{SCURL}}{{PKI}}.

AID
: Autonomic IDentifier. A self-managing *cryptonymous* identifier that MUST be self-certifying (self-authenticating) and MUST be encoded in CESR as a *qualified* cryptographic primitive. An AID MAY exhibit other self-managing properties such as transferable control using key *pre-rotation* which enables control over such an AID to persist in spite of key weakness or compromise due to exposure. Authoritative control over the identifier persists in spite of the evolution of the key-state.

Key State
: Includes the set of currently authoritative key-pairs for an AID and any other information necessary to secure or establish control over an AID.

Key Event
: Concretely, the serialized data structure of an entry in the key event log for an AID. Abstractly, the data structure itself. Key events come in different types and are used primarily to establish or change the authoritative set of keypairs and/or anchor other data to the authoritative set of keypairs at the point in the key event log actualized by a particular entry.

Establishment Event
: Key Event that establishes or changes the key-state which includes the current set of authoritative keypairs (key-state) for an AID.

Non-establishment Event
: Key Event that does not change the current key-state for an AID. Typically the purpose of a non-establishment event is to anchor external data to a given key state as established by the most recent prior establishment event for an AID.

Inception Event
: Establishment Event that provides the incepting information needed to derive an AID and establish its initial key-state.

Inception
: The operation of creating an AID by binding it to the initial set of authoritative key-pairs and any other associated information. This operation is made verifiable and duplicity evident upon acceptance as the *inception event* that begins the AID's KEL.

Rotation Event
: Establishment Event that provides the information needed to change the key-state which includes a change to the set of authoritative keypairs for an AID.

Rotation
: The operation of revoking and replacing the set of authoritative keypairs for an AID. This operation is made verifiable and duplicity evident upon acceptance as a *rotation event* that is appended to the AID's KEL.

Interaction Event
: Non-establishment Event that anchors external data to the key-state as established by the most recent prior establishment event.

KEL
:  Key Event Log. A verifiable data structure that is a backward and forward chained, signed, append-only log of key events for an AID. The first entry in a KEL MUST be the one and only Inception Event of that AID.

Version
: More than one version of a KEL for an AID exists when for any two instances of a KEL at least one event is unique between the two instances.

Verifiable
: A KEL is verifiable means all content in a KEL including the digests and the signatures on that content is verifiably compliant with respect to the KERI protocol. In other words, the KEL is internally consistent and has integrity vis-a-vis its backward and forward chaining digests and authenticity vis-a-vis its non-repudiable signatures. As a verifiable data structure, the KEL satisfies the KERI protocol-defined rules for that verifiability. This includes the cryptographic verification of any digests or signatures on the contents so digested or signed.

Duplicity
: Means the existence of more than one version of a verifiable KEL for a given AID. Because every event in a KEL must be signed with non-repudiable signatures any inconsistency between any two instances of the KEL for a given AID is provable evidence of duplicity on the part of the signers with respect to either or both the key-state of that AID and/or any anchored data at a given key-state.  A shorter KEL that does not differ in any of its events with respect to another but longer KEL is not duplicitous but merely incomplete.  To clarify, duplicity evident means that duplicity is provable via the presentation of a set of two or more mutually inconsistent but independently verifiable instances of a KEL.


Validator
: Any entity that evaluates one more AID's KEL in order to determine if it can rely on (trust) the key-state provided by that KEL. A necessary but insufficient condition for a valid KEL is it is verifiable i.e. is internally inconsistent with respect to compliance with the KERI protocol. An invalid KEL from the perspective of a Validator may be either unverifiable or it may be verifiable but duplicitous with respect to another verifiable version of that KEL.  Detected duplicity by a given validator means that the validator has seen more than one verifiable version of a KEL for a given AID. Reconciliable duplicity means that one and only one version of a KEL as seen by a validator is accepted as the authoritative version for that validator. Irreconcilable duplicity means that none of the versions of a KEL as seen by a validator are accepted as the authoritative one for that validator. The conditions for reconcilable duplicity are described later.


Message
: Consists of a serialized data structure that comprises its body and a set of serialized data structures that are its attachments. Attachments may include but are not limited to signatures on the body.

Key Event Message
: Message whose body is a key event and whose attachments may include signatures on its body.

Key Event Receipt
: Message whose body references a key event and whose attachments MUST include one or more signatures on that key event.



# Keypair Labeling Convention

In order to make key event expressions both clearer and more concise, we use a keypair labeling convention. When an AID's key state is dynamic, i.e. the set of controlling keypairs is transferable, then the keypair labels are indexed in order to represent the successive sets of keypairs that constitute the key state at any position in the KEL (key event log). To elaborate, we use indexes on the labels for AIDs that are transferable to indicate which set of keypairs is associated with the AID at any given point in its key state or KEL. In contrast, when the key state is static, i.e. the set of controlling keypairs is non-transferable then no indexes are needed because the key state never changes.

Recall that, a keypair is a two tuple, `(public, private)`, of the respective public and private keys in the keypair. For a given AID, the labeling convention uses an uppercase letter label to represent that AID. When the key state is dynamic, a superscripted index on that letter is used to indicate which keypair is used at a given key state. Alternatively, the index may be omitted when the context defines which keypair and which key state, such as, for example, the latest or current key state. To reiterate, when the key state is static no index is needed.

In general, without loss of specificity, we use an uppercase letter label to represent both an AID and when indexed to represent its keypair or keypairs at a given key state for that AID. In addition, when expressed in tuple form the uppercase letter also represents the public key and the lowercase letter represents the private key for a given keypair. For example, let `A` denote and AID, then let `A` also denote a keypair which may be also expressed in tuple form as `(A, a)`. Therefore, when referring to the keypair itself as a pair and not the individual members of the pair, either the uppercase label, `A`, or the tuple, `(A, a)`, may be used to refer to the keypair itself. When referring to the individual members of the keypair then the uppercase letter, `A`, refers to the public key, and the lowercase letter, `a`, refers to the private key.

As described above, an establishment key event may change the key state. Let the sequence of establishment events be indexed by the zero-based integer-valued variable `i`. Let the sequence of keypairs used to control an AID be indexed by the zero-based integer-valued variable `j`. When the set of controlling keypairs used at any time for a given key state includes only one member, then `i = j` for every keypair, and only one index is needed. But when the set of keypairs used at any time for a given key state includes more than one member, then `i ≠ j` for every keypair, and both indices are needed.

the former case, where only one index is needed because `i = j`, let the indexed keypair for AID, `A`, be denoted by *A<sup>j</sup>* or in tuple form by *(A<sup>j</sup>, a<sup>j</sup>)* where the keypair so indexed uses the j<sup>th</sup> keypair from the sequence of all keypairs.  The keypair sequence may be expressed as the list, *[A<sup>0</sup>, A<sup>1</sup>, A<sup>2</sup>, ...]*. The zero element in this sequence is denoted by A<sup>0</sup> or in tuple form by *(A<sup>0</sup>, a<sup>0</sup>)*.

In the latter case, where both indices are needed because `i ≠ j`, let the indexed keypair for AID, `A`, be tdenoted by *A<sup>i,j</sup>* or in tuple form by *(A<sup>i,j</sup>, a<sup>i,j</sup>)* where the keypair so indexed appears in the *i<sup>th</sup>* key state and uses the *j<sup>th</sup>* keypair from the sequence of all keypairs. Suppose, for example, that each key state uses three keypairs, then the sequence of the first two key states that consume the first six keypairs is given by the following list, *[A<sup>0,0</sup>, A<sup>0,1</sup>, A<sup>0,2</sup>, A<sup>1,3</sup>,  A<sup>1,4</sup>,  A<sup>1,5</sup>]*.

Ā


# Key Pre-rotation Details

ToDo describe the pre-rotated sequence of key sets (exposed and unexposed)

# Messages and Seals

Because adding the `d` field SAID to every key event message type will break all the explicit test vectors. Its no additional pain to normalize the field ordering across all message types and seals.
Originally all messages included an `i` field but that is not true anymore. So the changed field ordering is to put the fields that are common to all message types first in order followed by fields that are not common. The common fields are `v`, `t`, `d`.
The newly revised messages and seals are shown below.

## Message Field Labels

### SAIDs and KERI Label Convention Normalization

Because the order of appearance of fields is enforced in all KERI messages, where a label appears (in which message or which block in a message) adds the necessary context to fully determine its meaning.

### Special Label Ordering Requirements

The version string, `v`, field MUST be the first field when it appears. This enables a RegEx stream parser to consistently find the version string.

There are two other identifiers that appear after `v` when `v` is present or may appear first
when `v` is not present. These are `i` and `d`.

In this context, `i` is short for `ai`, which is short for the Autonomic IDentifier (AID). The AID given by the `i` field may also be thought of as a securely attributable identifier, authoritative identifier, authenticatable identifier, authorizing identifier, or authoring identifier. Because AIDs may be namespaced, the essential component of an AID is the cryptographically derived Controller identifier prefix. An AID MUST be self-certifying. An AID may be simply the Controller identifier prefix or may be namespaced as part of a W3C Decentralized IDentifier (DID) {{W3C_DID}}. Another way of thinking about an `i` field is that it is the identifier of the authoritative entity to which a statement may be securely attributed, thereby making the statement verifiably authentic via a non-repudiable signature made by that authoritative entity as the Controller of the private key(s).


### KERI Message Defined Element Labels

|Label|Description|Type|Notes|
|---|---|---|---|
|v| Version String| | |
|i| Identifier Prefix|  | |
|s| Sequence Number|  | |
|t| Message Type| | |
|te| Last received Event Message Type in Key State Notice | | |
|d| SAID of Event ||
|p| Prior Event SAID | | |
|kt| Keys Signing Threshold || |
|k| List of Signing Keys (ordered key set)| | |
|nt| Next Keys Signing Threshold || |
|n| List of Next Key Digests (ordered digest set) |   | |
|bt| Backer Threshold || |
|b| List of Backers  (ordered backer set) | | |
|br| List of Witnesses to Remove (ordered witness set) | | |
|ba| List of Witnesses to Add (ordered witness set) | | |
|c| List of Configuration Traits/Modes |  | |
|a| List of Anchors (seals) || |
|da| Delegator Anchor Seal in Delegated Event (Location Seal) | | Obsolete |
|di| Delegator Identifier Prefix  | | |
|rd| Merkle Tree Root Digest || |
|ee| Last Establishment Event Map | | |
|vn| Version Number ("major.minor")  |  | |

A label may have different values in different contexts but not a different value ***type***.


## Common Normalized ACDC Labels

`v` is version string
`d` is SAID of enclosing block or map
`i` is a KERI identifier AID
`a` is data attributes or data anchors


## Version String Field

Get from ACDC


# Event Messages


## Rotation


### Partial Participation in Rotation

The `nt` field is next threshold for the next establishment event.

With the additional field a validator is able to verify that both the set of signatures on a given rotation event both satisfies the original next threshold of signatures and public keys of that threshold satisficing set of signing public keys were part of the next next digest list committed too by the prior establishment event without revealing the next public keys of those signers that did not participate in the rotation.

Besides providing better fault tolerance to controller availability yet still preserving post-quantum protection, the partial rotation allows unused key pairs from non-participating rotation members to be reused as members of the new next pre-rotation set without exposing the associated public keys. This latter advantage has application to multi-sig thresholds where some of the members are escrow or custodial members where participation in every rotation may be cumbersome. The primary disadvantage of the partial rotation approach is that is is more verbose and consumes more bandwidth. However this is outweighed by the simplicity and increased security and fault tolerance of only one format for next threshold and next key digest list declaration. Moreover every rotation can now be a partial rotation since every establishment event provides a list of next thresholds in order. Order preservation is essential for fractionally weighted thresholds which order was not protected explicitly by the establishment events but had to be ensured out-of-band by the multi-sig members. Putting the ordering in-band allows an additional check by each member of a multi-sig group that indeed the digest for their own individual next public key is included in the next digest list in the proper position before signing. A validator also now can fully evaluate the next key state for degree of security vis-a-vis the type of multi-sig both group size and threshold.

The `k` field of a partial rotation provides the public keys of the participating signers in their same order of appearance in the previous next `n` field digest list. Non participating public keys are skipped. The `nt` field from the previous establishment event provides the satisficing threshold needed to accept the new rotation.
The `kt` field is the new signing threshold for the subset of public keys in the `k` field list. Both thresholds, `kt` from the current event and `nt` from the prior establishment event must be satisfied by the signers of any given rotation event.

The validator verifies the rotation against the original next digest list with the following procedure.
- the validator ensures that there is a corresponding entry in order in the previous `n` digest field list for the digest of each of the public keys in the `k` field list. This may be performed by an ordered search.
-  Starting with the digest of the first member of the `k` field and comparing it in turn in order starting with the first member of the previous `n` field list.
- When a match is found then the search resumes at the next member of each of the `k` and `n` lists until a corresponding match is found. Search resumes by repeating the prior step.
- the validator ensures that the attached signatures satisfy the original threshold given by the `nt` field of the prior establishment event where the signers are taken from the `k` field list of public keys. The attached indexed signature indexes refer to the order of appearance in the. `k` field, not the previous `n` field.

To reiterate, the signatures on the rotation event must meet the original next threshold given by the `ot` field. The new current signing threshold is provided by the `kt` field and the new current public signing keys are provided by the `k` field. The new next digest in the `n` field or `n` field list may or may not include some of all of the digests from the previous `n` field list that do not have corresponding entries in the `k` field list.

This approach allows any threshold satisficing set of signers to rotate to a new current set of signing keys that is a threshold satisficing subset of the previous next threshold without requiring knowledge of all the previous next public signing keys. Those members not represented by the public keys digests in the `k` field may be part of the new next digest or digest list because the underlying public keys were not disclosed by the rotation. This only may be applied when the previous next field, `n` is a list of digests not an XORed combination of the digests.

### Inception Event

When the AID in the `i` field is a self-addressing self-certifying AID, the new Inception Event has two
qualified digest fields. In this case both the `d` and `i` fields must have the same value. This means the digest suite's derivation code, used for the `i` field must be the same for the `d` field.
The derivation of the `d` and `i` fields is special. Both the `d` and `i` fields are replaced with dummy `#` characters of the length of the digest to be used. The digest of the Inception event is then computed and both the `d` and `i` fields are replaced with the qualified digest value. Validation of an inception event requires examining the `i` field's derivation code and if it is a digest-type then the `d` field must be identical otherwise the inception event is invalid.

When the AID is not self-addressing, i.e. the `i` field derivation code is not a digest. Then the `i` is given its value and the `d` field is replaced with dummy characters `#` of the correct length and then the digest is computed. This is the standard SAID algorithm.


## Inception Event Message

### Event Message Body

~~~json
{
  "v": "KERI10JSON0001ac_",
  "t": "icp",
  "d": "EL1L56LyoKrIofnn0oPChS4EyzMHEEk75INJohDS_Bug",
  "i": "EL1L56LyoKrIofnn0oPChS4EyzMHEEk75INJohDS_Bug",
  "s": "0",
  "kt": "2", // 2 of 3
  "k" :
    [
      "DnmwyZ-i0H3ULvad8JZAoTNZaU6JR2YAfSVPzh5CMzS6b",
      "DZaU6JR2nmwyZ-VPzhzSslkie8c8TNZaU6J6bVPzhzS6b",
      "Dd8JZAoTNnmwyZ-i0H3U3ZaU6JR2LvYAfSVPzhzS6b5CM"
    ],
  "nt": "3",  // 3 of 5
  "n" :
    [
      "ETNZH3ULvYawyZ-i0d8JZU6JR2nmAoAfSVPzhzS6b5CM",
      "EYAfSVPzhzaU6JR2nmoTNZH3ULvwyZb6b5CMi0d8JZAS",
      "EnmwyZdi0d8JZAoTNZYAfSVPzhzaU6JR2H3ULvS6b5CM",
      "ETNZH3ULvS6bYAfSVPzhzaU6JR2nmwyZfi0d8JZ5s8bk",
      "EJR2nmwyZ2i0dzaU6ULvS6b5CM8JZAoTNZH3YAfSVPzh",
    ],
  "bt": "2",
  "b":
    [
      "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
      "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
      "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
    ],
  "c": [],
  "a": []
}
~~~



## Rotation Event Message

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "rot",
  "d" : "E0d8JJR2nmwyYAfZAoTNZH3ULvaU6Z-iSVPzhzS6b5CM",
  "i" : "EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM",
  "s" : "1",
  "p" : "EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM",
  "kt": "2", // 2 of 3
  "k" :
    [
      "DnmwyZ-i0H3ULvad8JZAoTNZaU6JR2YAfSVPzh5CMzS6b",
      "DZaU6JR2nmwyZ-VPzhzSslkie8c8TNZaU6J6bVPzhzS6b",
      "Dd8JZAoTNnmwyZ-i0H3U3ZaU6JR2LvYAfSVPzhzS6b5CM"
    ],
  "nt": "3",  // 3 of 5
  "n" :
    [
      "ETNZH3ULvYawyZ-i0d8JZU6JR2nmAoAfSVPzhzS6b5CM",
      "EYAfSVPzhzaU6JR2nmoTNZH3ULvwyZb6b5CMi0d8JZAS",
      "EnmwyZdi0d8JZAoTNZYAfSVPzhzaU6JR2H3ULvS6b5CM",
      "ETNZH3ULvS6bYAfSVPzhzaU6JR2nmwyZfi0d8JZ5s8bk",
      "EJR2nmwyZ2i0dzaU6ULvS6b5CM8JZAoTNZH3YAfSVPzh",
    ],
  "bt": "1",
  "ba": ["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],
  "br": ["DH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8TNZJZAo5CM"],
  "a" : []
}
~~~


### Interaction Event  (Also delegating Interaction)

~~~json
{
  "v": "KERI10JSON00011c_",
  "t": "isn",
  "d": "E0d8JJR2nmwyYAfZAoTNZH3ULvaU6Z-iSVPzhzS6b5CM",
  "i": "EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM",
  "s": "2",
  "p": "EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM",
  "a":
  [
    {
      "d": "ELvaU6Z-i0d8JJR2nmwyYAZAoTNZH3UfSVPzhzS6b5CM",
      "i": "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",
      "s": "1"
    }
  ]
}
~~~

### Delegated Inception Event

~~~json
{
  "v": "KERI10JSON0001ac_",
  "t": "icp",
  "d": "EL1L56LyoKrIofnn0oPChS4EyzMHEEk75INJohDS_Bug",
  "i": "EL1L56LyoKrIofnn0oPChS4EyzMHEEk75INJohDS_Bug",
  "s": "0",
  "kt": "2", // 2 of 3
  "k" :
    [
      "DnmwyZ-i0H3ULvad8JZAoTNZaU6JR2YAfSVPzh5CMzS6b",
      "DZaU6JR2nmwyZ-VPzhzSslkie8c8TNZaU6J6bVPzhzS6b",
      "Dd8JZAoTNnmwyZ-i0H3U3ZaU6JR2LvYAfSVPzhzS6b5CM"
    ],
  "nt": "3",  // 3 of 5
  "n" :
    [
      "ETNZH3ULvYawyZ-i0d8JZU6JR2nmAoAfSVPzhzS6b5CM",
      "EYAfSVPzhzaU6JR2nmoTNZH3ULvwyZb6b5CMi0d8JZAS",
      "EnmwyZdi0d8JZAoTNZYAfSVPzhzaU6JR2H3ULvS6b5CM",
      "ETNZH3ULvS6bYAfSVPzhzaU6JR2nmwyZfi0d8JZ5s8bk",
      "EJR2nmwyZ2i0dzaU6ULvS6b5CM8JZAoTNZH3YAfSVPzh",
    ],
  "bt": "2",
  "b":
    [
      "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
      "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
      "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
    ],
  "c": [],
  "a": [],
  "di": "EJJR2nmwyYAZAoTNZH3ULvaU6Z-i0d8fSVPzhzS6b5CM"
}
~~~



### Delegated Rotation Event

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "drt",
  "d" : "E0d8JJR2nmwyYAfZAoTNZH3ULvaU6Z-iSVPzhzS6b5CM",
  "i" : "EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM",
  "s" : "1",
  "p" : "EULvaU6JR2nmwyZ-i0d8JZAoTNZH3YAfSVPzhzS6b5CM",
  "kt": "2", // 2 of 3
  "k" :
    [
      "DnmwyZ-i0H3ULvad8JZAoTNZaU6JR2YAfSVPzh5CMzS6b",
      "DZaU6JR2nmwyZ-VPzhzSslkie8c8TNZaU6J6bVPzhzS6b",
      "Dd8JZAoTNnmwyZ-i0H3U3ZaU6JR2LvYAfSVPzhzS6b5CM"
    ],
  "nt": "3",  // 3 of 5
  "n" :
    [
      "ETNZH3ULvYawyZ-i0d8JZU6JR2nmAoAfSVPzhzS6b5CM",
      "EYAfSVPzhzaU6JR2nmoTNZH3ULvwyZb6b5CMi0d8JZAS",
      "EnmwyZdi0d8JZAoTNZYAfSVPzhzaU6JR2H3ULvS6b5CM",
      "ETNZH3ULvS6bYAfSVPzhzaU6JR2nmwyZfi0d8JZ5s8bk",
      "EJR2nmwyZ2i0dzaU6ULvS6b5CM8JZAoTNZH3YAfSVPzh",
    ],
  "bt": "1",
  "ba":  ["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],
  "br":  ["DH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8TNZJZAo5CM"],
  "a" :[]
  "di" : "EJJR2nmwyYAZAoTNZH3ULvaU6Z-i0d8fSVPzhzS6b5CM"
}
~~~


## Receipts
### Non-Transferable Prefix Signer Receipt
For receipts, the `d` field is the SAID of the associated event, not the receipt message itself.


~~~json
{
  "v": "KERI10JSON00011c_",
  "t": "rct",
  "d": "DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
  "i": "AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
  "s": "1"
}
~~~

### Transferable Prefix Signer Receipt
For receipts, the `d` field is the SAID of the associated event, not the receipt message itself.

~~~json
{
  "v": "KERI10JSON00011c_",
  "t": "vrc",
  "d": "DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
  "i": "AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
  "s": "1",
  "a":
    {
      "d": "DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
      "i": "AYAfSVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULv",
      "s": "4"
    }
}
~~~

## Seals

### Digest Seal

~~~json
{
  "d": "Eabcde..."
}
~~~

### Merkle Tree Root Digest Seal

~~~json
{
  "rd": "Eabcde8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM"
}
~~~

### Backer Seal

~~~json
{
  "bi": "BACDEFG8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
  "d" : "EFGKDDA8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM"
}

~~~

### Event Seal
~~~json
{

  "i": "Ebietyi8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM.",
  "s": "3",
  "d": "Eabcde8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM"
}
~~~


### Last Establishment Event Seal

~~~json
{
  "i": "BACDEFG8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
}

~~~



## Other Messages

### Query Message

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "qry",
  "d" : "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r" : "logs",
  "rr": "log/processor",
  "q" :
  {
    "i" : "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
    "s" : "5",
    "dt": "2020-08-01T12:20:05.123456+00:00",
  }
}
~~~

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "qry",
  "d" : "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r" : "logs",
  "rr": "log/processor",
  "q" :
  {
    "d" : "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
    "i" : "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
    "s" : "5",
    "dt": "2020-08-01T12:20:05.123456+00:00",
  }
}
~~~

### Reply Message

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "rpy",
  "d" : "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r" : "logs/processor",
  "a" :
  {
    "i": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
    "name": "John Jones",
    "role": "Founder",
  }
}
~~~

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "rpy",
  "d" : "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r" : "logs/processor",
  "a" :
  {
    "d":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
    "i": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
    "name": "John Jones",
    "role": "Founder",
  }
}
~~~



### Bare Message

Reference to the anchoring seal is provided as an attachment to the bare, `bre` message.
A bare, 'bre', message is a SAD item with an associated derived SAID in its 'd' field.

~~~json
{
  "v": "KERI10JSON00011c_",
  "t": "bre",
  "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "r": "process/sealed/data",
  "a":
  {
    "d": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
    "i": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
    "dt": "2020-08-22T17:50:12.988921+00:00",
    "name": "John Jones",
    "role": "Founder",
  }
}
~~~

### Prod Message

~~~json
{
  "v": "KERI10JSON00011c_",
  "t": "prd",
  "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "r": "sealed/data",
  "rr": "process/sealed/data"
  "q":
  {
     d" : "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
    "i" : "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
    "s" : "5",
    "ri": "EAoTNZH3ULvYAfSVPzhzS6baU6JR2nmwyZ-i0d8JZ5CM",
    "dd": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"
  }
}
~~~

### Exchange Message (exchange)

~~~json
{
  "v": "KERI10JSON00006a_",
  "t": "exn",
  "d": "EF3Dd96ATbbMIZgUBBwuFAWx3_8s5XSt_0jeyCRXq_bM",
  "dt": "2021-11-12T19:11:19.342132+00:00",
  "r": "/echo",
  "rr": "/echo/response",
  "a": {
    "msg": "test"
  }
}
~~~

## Notices Embedded in Reply Messages

### Key State Notice (KSN)

~~~json
{
  "v": "KERI10JSON0001d9_",
  "d": "EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM",
  "i": "E4BsxCYUtUx3d6UkDVIQ9Ke3CLQfqWBfICSmjIzkS1u4",
  "s": "0",
  "p": "",
  "f": "0",
  "dt": "2021-01-01T00:00:00.000000+00:00",
  "et": "icp",
  "kt": "1",
  "k": [
    "DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"
  ],
  "n": "E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss",
  "bt": "1",
  "b": [
    "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"
  ],
  "c": [],
  "ee": {
    "s": "0",
    "d": "EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM",
    "br": [],
    "ba": []
  },
  "di": ""
}
~~~

#### Embedded in Reply

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "rpy",
  "d" : "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r" : "/ksn/BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY",
  "a" :
    {
      "v": "KERI10JSON0001d9_",
      "d": "EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM",
      "i": "E4BsxCYUtUx3d6UkDVIQ9Ke3CLQfqWBfICSmjIzkS1u4",
      "s": "0",
      "p": "",
      "f": "0",
      "dt": "2021-01-01T00:00:00.000000+00:00",
      "et": "icp",
      "kt": "1",
      "k": [
        "DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"
      ],
      "n": "E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss",
      "bt": "1",
      "b": [
        "BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"
      ],
      "c": [],
      "ee": {
        "s": "0",
        "d": "EYk4PigtRsCd5W2so98c8r8aeRHoixJK7ntv9mTrZPmM",
        "br": [],
        "ba": []
      },
      "di": ""
    }
}
~~~

### Transaction State Notice (TSN)

~~~json
{
  "v": "KERI10JSON0001b0_",
  "d": "EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqbI0",
  "i": "EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",
  "s": "1",
  "ii": "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY",
  "dt": "2021-01-01T00:00:00.000000+00:00",
  "et": "vrt",
  "a": {
    "s": 2,
    "d": "Ef12IRHtb_gVo5ClaHHNV90b43adA0f8vRs3jeU-AstY"
  },
  "bt": "1",
  "br": [],
  "ba": [
    "BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"
  ],
  "b": [
    "BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"
  ],
  "c": []
}
~~~

#### Embedded in Reply

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "rpy",
  "d" : "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "dt": "2020-08-22T17:50:12.988921+00:00",
  "r" : "/ksn/registry/BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU",
  "a" :
    {
      "v": "KERI10JSON0001b0_",
      "d": "EpltHxeKueSR1a7e0_oSAhgO6U7VDnX7x4KqNCwBqbI0",
      "i": "EoN_Ln_JpgqsIys-jDOH8oWdxgWqs7hzkDGeLWHb9vSY",
      "s": "1",
      "ii": "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY",
      "dt": "2021-01-01T00:00:00.000000+00:00",
      "et": "vrt",
      "a": {
        "s": 2,
        "d": "Ef12IRHtb_gVo5ClaHHNV90b43adA0f8vRs3jeU-AstY"
      },
      "bt": "1",
      "br": [],
      "ba": [
        "BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"
      ],
      "b": [
        "BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"
      ],
      "c": []
    }
}
~~~

## Transaction Event Log Messages

### Registry Inception Event

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "vcp",
  "d" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "i" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "ii": "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8",
  "s" : "0",
  "bt": "1",
  "b" : ["BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s"],
  "c" : ["NB"]
}

~~~

### Registry Rotation Event

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "vrt",
  "d" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "i" : "E_D0eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqA7BxL",
  "s" : "2",
  "p" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "bt": "1",
  "br" : ["BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s"],
  "ba" : []
}
~~~

### Backerless Credential Issuance

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "iss",
  "d" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "i" : "E_D0eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqA7BxL",
  "s" : "0",
  "ri" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "dt": "2020-08-01T12:20:05.123456+00:00"
}
~~~

### Backerless Credential Revocation

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "rev",
  "d" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "i" : "E_D0eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqA7BxL",
  "s" : "1",
  "p" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "ri" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "dt": "2020-08-01T12:20:05.123456+00:00"
}
~~~

### Backer Credential Issuance

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "bis",
  "d" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "i" : "E_D0eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqA7BxL",
  "s" : "0",
  "ri" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "ra" : {
      "d": "E8ipype17kJlQfYp3gcF3F1PNKfdX6vpOLXU8YyykB5o",
      "i": "EFvQCx4-O9bb9fGzY7KgbPeUtjtU0M4OBQWsiIk8za24",
      "s": 0
  }
  "dt": "2020-08-01T12:20:05.123456+00:00"
}
~~~

### Backer Credential Revocation

~~~json
{
  "v" : "KERI10JSON00011c_",
  "t" : "brv",
  "d" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "i" : "E_D0eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqA7BxL",
  "s" : "1",
  "p" : "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A",
  "ri" : "EvxMACzQxU2rDj-X5SPDZYtUn56i4fjjH8yDRFRzaMfI",
  "ra" : {
      "d": "E8ipype17kJlQfYp3gcF3F1PNKfdX6vpOLXU8YyykB5o",
      "i": "EFvQCx4-O9bb9fGzY7KgbPeUtjtU0M4OBQWsiIk8za24",
      "s": 0
  }
  "dt": "2020-08-01T12:20:05.123456+00:00"
}
~~~




# Appendix: Cryptographic Strength and Security

## Cryptographic Strength

For crypto-systems with *perfect-security*, the critical design parameter is the number of bits of entropy needed to resist any practical brute force attack. In other words, when a large random or pseudo-random number from a cryptographic strength pseudo-random number generator (CSPRNG) {{CSPRNG}} expressed as a string of characters is used as a seed or private key to a cryptosystem with *perfect-security*, the critical design parameter is determined by the amount of random entropy in that string needed to withstand a brute force attack. Any subsequent cryptographic operations must preserve that minimum level of cryptographic strength. In information theory {{IThry}}{{ITPS}} the entropy of a message or string of characters is measured in bits. Another way of saying this is that the degree of randomness of a string of characters can be measured by the number of bits of entropy in that string.  Assuming conventional non-quantum computers, the convention wisdom is that, for systems with information-theoretic or perfect security, the seed/key needs to have on the order of 128 bits (16 bytes, 32 hex characters) of entropy to practically withstand any brute force attack {{TMCrypto}}{{QCHC}}. A cryptographic quality random or pseudo-random number expressed as a string of characters will have essentially as many bits of entropy as the number of bits in the number. For other crypto-systems such as digital signatures that do not have perfect security, the size of the seed/key may need to be much larger than 128 bits in order to maintain 128 bits of cryptographic strength.

An N-bit long base-2 random number has 2<sup>N</sup> different possible values. Given that no other information is available to an attacker with perfect security, the attacker may need to try every possible value before finding the correct one. Thus the number of attempts that the attacker would have to try maybe as much as 2<sup>N-1</sup>.  Given available computing power, one can easily show that 128 is a large enough N to make brute force attack computationally infeasible.

Let's suppose that the adversary has access to supercomputers. Current supercomputers can perform on the order of one quadrillion operations per second. Individual CPU cores can only perform about 4 billion operations per second, but a supercomputer will parallelly employ many cores. A quadrillion is approximately 2<sup>50</sup> = 1,125,899,906,842,624. Suppose somehow an adversary had control over one million (2<sup>20</sup> = 1,048,576) supercomputers which could be employed in parallel when mounting a brute force attack. The adversary could then try 2<sup>50</sup> * 2<sup>20</sup> = 2<sup>70</sup> values per second (assuming very conservatively that each try only took one operation).
There are about 3600 * 24 * 365 = 313,536,000 = 2<sup>log<sub>2</sub>313536000</sup>=2<sup>24.91</sup> ~= 2<sup>25</sup> seconds in a year. Thus this set of a million super computers could try 2<sup>50+20+25</sup> = 2<sup>95</sup> values per year. For a 128-bit random number this means that the adversary would need on the order of 2<sup>128-95</sup> = 2<sup>33</sup> = 8,589,934,592 years to find the right value. This assumes that the value of breaking the cryptosystem is worth the expense of that much computing power. Consequently, a cryptosystem with perfect security and 128 bits of cryptographic strength is computationally infeasible to break via brute force attack.

## Information Theoretic Security and Perfect Security

The highest level of cryptographic security with respect to a cryptographic secret (seed, salt, or private key) is called  *information-theoretic security* {{ITPS}}. A cryptosystem that has this level of security cannot be broken algorithmically even if the adversary has nearly unlimited computing power including quantum computing. It must be broken by brute force if at all. Brute force means that in order to guarantee success the adversary must search for every combination of key or seed. A special case of *information-theoretic security* is called *perfect-security* {{ITPS}}.  *Perfect-security* means that the ciphertext provides no information about the key. There are two well-known cryptosystems that exhibit *perfect security*. The first is a *one-time-pad* (OTP) or Vernum Cipher {{OTP}}{{VCphr}}, the other is *secret splitting* {{SSplt}}, a type of secret sharing {{SShr}} that uses the same technique as a *one-time-pad*.





# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

KERI Community at the WebOfTrust Github project.
