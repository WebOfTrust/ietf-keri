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
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022
    
  CESR_ID:
    target: https://github.com/WebOfTrust/ietf-cesr
    title: IETF CESR (Composable Event Streaming Representation) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022
    
  SAID_ID:
    target: https://github.com/WebOfTrust/ietf-said
    title: IETF SAID (Self-Addressing IDentifier) Internet Draft
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
    date: 2022
    
  RFC6901: 
    target: https://datatracker.ietf.org/doc/html/rfc6901 
    title: JavaScript Object Notation (JSON) Pointer 
    author: 
      -
        name: Paul C. Bryan 
      -
        name: Kris Zyp 
      -
        name: Mark Nottingham 
    date: 2003

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
    author:
      -
        ins: C. Bormann
        name: Carsten Bormann
      -
        ins: P. Hoffman
        name: Paul Hoffman
    date: 2020-12-04
    
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
    author:
        ins: S. Smith
        name: Samuel M. Smith
        org: ProSapien LLC
    date: 2021
    
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
    seriesinfo: 2021 IEEE Symposium on Security and Privacy (SP)
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
    date: 2021-05-24

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
    
  IDSys:
    target: https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/Identity-System-Essentials.pdf
    title: Identity System Essentials 
    
  Hash:
    target: https://en.wikipedia.org/wiki/Cryptographic_hash_function
    title: Cryptographic Hash Function 

  W3C_DID:
    target: https://w3c-ccg.github.io/did-spec/
    title: W3C Decentralized Identifiers (DIDs) v1.0



--- abstract

An identity system-based secure overlay for the Internet is presented. This is based on a Key Event Receipt Infrastructure (KERI) or the KERI protocol {{KERI}}{{KERI_ID}} . This includes a primary root-of-trust in self-certifying identifiers (SCIDs). It presents a formalism for Autonomic Identifiers (AIDs) and Autonomic Namespaces (ANs). They are part of an Autonomic Identity System (AIS). This system uses the design principle of minimally sufficient means to provide a candidate trust spanning layer for the internet. Associated with this system is a decentralized key management infrastructure (DKMI). The primary root-of-trust are self-certifying identifiers that are strongly bound at issuance to a cryptographic signing (public, private) key-pair. These are self-contained until/unless control needs to be transferred to a new key-pair. In that event an append-only chained key-event log of signed transfer statements provides end verifiable control provenance. This makes intervening operational infrastructure replaceable because the event logs may be served up by any infrastructure including ambient infrastructure. End verifiable logs on ambient infrastructure enable ambient verifiability (verifiable by anyone, anywhere, at anytime). 
The primary key management operation is key rotation (transference) via a novel key pre-rotation scheme. Two primary trust modalities motivated the design, these are a direct (one-to-one) mode and an indirect (one-to-any) mode. The indirect mode depends on witnessed key event receipt logs (KERL) as a secondary root-of-trust for validating events. This gives rise to the acronym KERI for key event receipt infrastructure. In the direct mode, the identity controller establishes control via verified signatures of the controlling key-pair. The indirect mode extends that trust basis with witnessed key event receipt logs (KERL) for validating events. The security and accountability guarantees of indirect mode are provided by KA2CE or KERI’s Agreement Algorithm for Control Establishment among a set of witnesses. 
The KA2CE approach may be much more performant and scalable than more complex approaches that depend on a total ordering distributed consensus ledger. Nevertheless, KERI may employ a distributed consensus ledger when other considerations make it the best choice. The KERI approach to DKMI allows for more granular composition. Moreover, because KERI is event streamed it enables DKMI that operates in-stride with data events streaming applications such as web 3.0, IoT, and others where performance and scalability are more important. The core KERI engine is identifier namespace independent. This makes KERI a candidate for a universal portable DKMI {{KERI}}{{KERI_ID}}. 


--- middle

# Introduction

The major motivation for this work is to provide a secure decentralized foundation of trust for the Internet as a trustable spanning layer. A major flaw in the original design of the Internet Protocol was that it had a security layer (i.e. Session or Presentation layers). There was no built-in mechanism for security. Specifically, the IP packet header includes a source address field to indicate the IP address of the device that sent the packet. Because the source address may be forged, a recipient may not know if the packet was sent by an imposter. Anyone can forge an IP (Internet Protocol) packet. This means that security mechanisms for the Internet must be overlaid (bolted-on). KERI provides such a security overlay.



# KERI Message and Seal Formats

Because adding the `d` field SAID to every key event message type will break all the explicit test vectors. Its no additional pain to normalize the field ordering across all message types and seals.
Originally all messages included an `i` field but that is not true any more. So the changed field ordering is to put the fields that are common to all message types first in order followed by fields that are not common. The common fields are `v`, `t`, `d`.
The newly revised messages and seals are shown below.

## Field Labels

### SAIDs and KERI Label Convention Normalization

Because the order of appearance of fields is enforced in all KERI messages, where a label appears (in which message or which block in a message) adds the necessary context to fully determine its meaning.  

### Special Label Ordering Requirements

The version string, `v`, field MUST be the first field when it appears. This enables a RegEx stream parser to consistently find the version string.

There are two other identifiers that appear after `v` when `v` is present or may appear first
when `v` is not present. These are `i` and `d`. 

In this context, `i` is short for `ai`, which is short for the Autonomic IDentifier (AID). The AID given by the `i` field may also be thought of as a securely attributable identifier, authoritative identifier, authenticatable identifier, authorizing identifier, or authoring identifier. Because AIDs may be namespaced, the essential component of an AID is the cryptographically derived Controller identifier prefix. An AID MUST be self-certifying. An AID may be simply the Controller identifier prefix or may be namespaced as part of a W3C Decentralized IDentifier (DID) {{W3C_DID}}. Another way of thinking about an `i` field is that it is the identifier of the authoritative entity to which a statement may be securely attributed, thereby making the statement verifiably authentic via a non-repudiable signature made by that authoritative entity as the Controller of the private key(s).


### KERI Defined Element Labels

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





## Event Messages

The `nt` field is next threshold for the next establishment event.

With the additional field a validator is able to verify that both the set of signatures on a given rotation event both satisfies the original next threshold of signatures and public keys of that threshold satisficing set of signing public keys were part of the next next digest list committed too by the prior establishment event without revealing the next public keys of those signers that did not participate in the rotation. 

Besides providing better fault tolerance to controller availability yet still preserving post-quantum protection, the partial rotation allows unused key pairs from non-participating rotation members to be reused as members of the new next pre-rotation set without exposing the associated public keys. This latter advantage has application to multi-sig thresholds where some of the members are escrow or custodial members where participation in every rotation may be cumbersome. The primary disadvantage of the partial rotation approach is that is is more verbose and consumes more bandwidth. However this is outweighed by the simplicity and increased security and fault tolerance of only one format for next threshold and next key digest list declaration. Moreover every rotation can now be a partial rotation since every establishment event provides a list of next thresholds in order. Order preservation is essential for fractionally weighted thresholds which order was not protected explicitly by the establishment events but had to be ensured out-of-band by the multi-sig members. Putting the ordering in-band allows an additional check by each member of a multi-sig group that indeed the digest for their own individual next public key is included in the next digest list in the proper position before signing. A validator also now can fully evaluate the next key state for degree of security vis-a-vis the type of multi-sig both group size and threshold.

The `k` field of a partial rotation provides the public keys of the participating signers in their same order of appearance in the previous next `n` field digest list. Non participating public keys are skipped. The `nt` field from the previous establishment event provides the satisficing threshold needed to accept the new rotation.
The `kt` field is the new signing threshold for the subset of public keys in the `k` field list. Both thresholds, `kt` from the current event and `nt` from the prior establishment event must be satisfied by the signers of any given rotation event.

The validator verifies the rotation against the original next digest list with the following procedure. 
- the validator ensures that there is a corresponding entry in order in the previous `n` digest field list for the digest of each of the public keys in the `k` field list. This may be performed by an ordered search. 
-  Starting with the digest of the first member of the `k` field and comparing it in turn in order starting with the first member of the previous `n` field list. 
- When a match is found then the search resumes at the next member of each of the `k` and `n` lists until a corresponding match is found. Search resumes by repeating prior step.
- the validator ensures that the attached signatures satisfy the original threshold given by the `nt` field of the prior establishment event where the signers are taken from the `k` field list of public keys. Attached indexed signature indexes refer to the order of appearance in the. `k` field not the previous `n` field.

To reiterate, the signatures on the the rotation event must meet the original next threshold given by the `ot` field. The new current signing threshold is provided by the `kt` field and the new current public signing keys are provided by the `k` field. The new next digest in the `n` field or `n` field list may or may not include some of all of the digests from the previous `n` field list that do not have corresponding entries in the `k` field list.

This approach allows any threshold satisficing set of signers to rotate to a new current set of signing keys that is a threshold satisficing subset of the previous next threshold without requiring knowledge of all the previous next public signing keys. Those members not represented by the public keys digests in the `k` field may be part of the new next digest or digest list because the underlying public keys were not disclosed by the rotation. This only may be applied when the previous next field, `n` is a list of digests not an XORed combination of the digests.

### Inception Event
When the AID in the `i` field is a self-addressing self-certifying AID, the new Inception Event has two
derived digest fields. In this case both the `d` and `i` fields must have the same value. This means the digest suite's derivation code, used for the `i` field must be the same for the `d` field.
The derivation of the `d` and `i` fields is special. Both the `d` and `i` fields are replaced with dummy `#` characters of the length of the digest to be used. The digest of the Inception event is then computed and both the `d` and `i` fields are replaced with the fully qualified digest value. Validation of an inception event requires examining the `i` field's derivation code and if it is a digest type then the `d` field must be identical otherwise the inception event is invalid.

When the AID is not self-addressing, i.e. the `i` field  derivation code is not a digest. Then the `i` is given its value and the `d` field is replaced with dummy characters `#` of the correct length and then the digest is computed. This is the standard SAID algorithm.




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



### Rotation Event
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
For receipts the `d` field is the SAID of the asssociated event not the receipt message itself.


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
For receipts the `d` field is the SAID of the asssociated event not the receipt message itself.

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
  "d": "Eabcde8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
  "i": "Ebietyi8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM.",
  "s": "3"
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

~~~json
{ 
  "v": "KERI10JSON00011c_",
  "t": "bar",
  "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "r": "sealed/processor",
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
  "t": "pro",
  "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
  "r": "sealed/processor",
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

For crypto-systems with *perfect-security*, the critical design parameter is the number of bits of entropy needed to resist any practical brute force attack. In other words, when a large random or pseudo-random number from a cryptographic strength pseudo-random number generator (CSPRNG) {{CSPRNG}} expressed as a string of characters is used as a seed or private key to a cryptosystem with *perfect-security*, the critical design parameter is determined by the amount of random entropy in that string needed to withstand a brute force attack. Any subsequent cryptographic operations must preserve that minimum level of cryptographic strength. In information theory {{IThry}}{{ITPS}} the entropy of a message or string of characters is measured in bits. Another way of saying this is that the degree of randomness of a string of characters can be measured by the number of bits of entropy in that string.  Assuming conventional non-quantum computers, the convention wisdom is that, for systems with information-theoretic or perfect security, the seed/key needs to have on the order of 128 bits (16 bytes, 32 hex characters) of entropy to practically withstand any brute force attack. A cryptographic quality random or pseudo-random number expressed as a string of characters will have essentially as many bits of entropy as the number of bits in the number. For other crypto-systems such as digital signatures that do not have perfect security, the size of the seed/key may need to be much larger than 128 bits in order to maintain 128 bits of cryptographic strength.

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

TODO acknowledge.
