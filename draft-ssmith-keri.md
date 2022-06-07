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


--- abstract

This is the abstract


--- middle

# Introduction
This is the middle


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
