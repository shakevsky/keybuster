from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1.type.univ import Sequence, Integer, Boolean, Enumerated, OctetString, Null, SetOf
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode


class RootOfTrust(Sequence):
    """
    RootOfTrust ::= SEQUENCE {
        verifiedBootKey     OCTET_STRING
        deviceLocked        BOOLEAN
        verifiedBootState   ENUMERATED
        verifiedBootHash    OCTET_STRING
    }
    """

    componentType = NamedTypes(
        NamedType('verifiedBootKey', OctetString()),
        NamedType('deviceLocked', Boolean()),
        NamedType('verifiedBootKey', Enumerated()),
        NamedType('verifiedBootHash', OctetString())
    )


class AuthorizationList(Sequence):
    """
    AuthorizationList ::= SEQUENCE {
        purpose  [1] EXPLICIT SET OF INTEGER OPTIONAL,
        algorithm  [2] EXPLICIT INTEGER OPTIONAL,
        keySize  [3] EXPLICIT INTEGER OPTIONAL,
        digest  [5] EXPLICIT SET OF INTEGER OPTIONAL,
        padding  [6] EXPLICIT SET OF INTEGER OPTIONAL,
        ecCurve  [10] EXPLICIT INTEGER OPTIONAL,
        rsaPublicExponent  [200] EXPLICIT INTEGER OPTIONAL,
        rollbackResistance  [303] EXPLICIT NULL OPTIONAL,
        activeDateTime  [400] EXPLICIT INTEGER OPTIONAL,
        originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
        usageExpireDateTime  [402] EXPLICIT INTEGER OPTIONAL,
        noAuthRequired  [503] EXPLICIT NULL OPTIONAL,
        userAuthType  [504] EXPLICIT INTEGER OPTIONAL,
        authTimeout  [505] EXPLICIT INTEGER OPTIONAL,
        allowWhileOnBody  [506] EXPLICIT NULL OPTIONAL,
        trustedUserPresenceRequired  [507] EXPLICIT NULL OPTIONAL,
        trustedConfirmationRequired  [508] EXPLICIT NULL OPTIONAL,
        unlockedDeviceRequired  [509] EXPLICIT NULL OPTIONAL,
        allApplications  [600] EXPLICIT NULL OPTIONAL,
        applicationId  [601] EXPLICIT OCTET_STRING OPTIONAL,
        creationDateTime  [701] EXPLICIT INTEGER OPTIONAL,
        origin  [702] EXPLICIT INTEGER OPTIONAL,
        rootOfTrust  [704] EXPLICIT RootOfTrust OPTIONAL,
        osVersion  [705] EXPLICIT INTEGER OPTIONAL,
        osPatchLevel  [706] EXPLICIT INTEGER OPTIONAL,
        attestationApplicationId  [709] EXPLICIT OCTET_STRING OPTIONAL,
        attestationIdBrand  [710] EXPLICIT OCTET_STRING OPTIONAL,
        attestationIdDevice  [711] EXPLICIT OCTET_STRING OPTIONAL,
        attestationIdProduct  [712] EXPLICIT OCTET_STRING OPTIONAL,
        attestationIdSerial  [713] EXPLICIT OCTET_STRING OPTIONAL,
        attestationIdImei  [714] EXPLICIT OCTET_STRING OPTIONAL,
        attestationIdMeid  [715] EXPLICIT OCTET_STRING OPTIONAL,
        attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL,
        attestationIdModel  [717] EXPLICIT OCTET_STRING OPTIONAL,
        vendorPatchLevel  [718] EXPLICIT INTEGER OPTIONAL,
        bootPatchLevel  [719] EXPLICIT INTEGER OPTIONAL,
    }
    """

    componentType = NamedTypes(
        OptionalNamedType('purpose', SetOf(componentType=Integer()).subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 1))),
        OptionalNamedType('algorithm', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 2))),
        OptionalNamedType('keySize', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 3))),
        OptionalNamedType('digest', SetOf(componentType=Integer()).subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 5))),
        OptionalNamedType('padding', SetOf(componentType=Integer()).subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 6))),
        OptionalNamedType('ecCurve', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 10))),
        OptionalNamedType('rsaPublicExponent', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 200))),
        OptionalNamedType('rollbackResistance', Null().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 303))),
        OptionalNamedType('activeDateTime', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 400))),
        OptionalNamedType('originationExpireDateTime', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 401))),
        OptionalNamedType('usageExpireDateTime', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 402))),
        OptionalNamedType('noAuthRequired', Null().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 503))),
        OptionalNamedType('userAuthType', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 504))),
        OptionalNamedType('authTimeout', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 505))),
        OptionalNamedType('allowWhileOnBody', Null().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 506))),
        OptionalNamedType('trustedUserPresenceRequired', Null().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 507))),
        OptionalNamedType('trustedConfirmationRequired', Null().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 508))),
        OptionalNamedType('unlockedDeviceRequired', Null().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 509))),
        OptionalNamedType('allApplications', Null().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 600))),
        OptionalNamedType('applicationId', OctetString().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 601))),
        OptionalNamedType('creationDateTime', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 701))),
        OptionalNamedType('origin', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 702))),
        OptionalNamedType('rootOfTrust', RootOfTrust().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 704))),
        OptionalNamedType('osVersion', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 705))),
        OptionalNamedType('osPatchLevel', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 706))),
        OptionalNamedType('attestationApplicationId', OctetString().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 709))),
        OptionalNamedType('attestationIdBrand', OctetString().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 710))),
        OptionalNamedType('attestationIdDevice', OctetString().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 711))),
        OptionalNamedType('attestationIdProduct', OctetString().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 712))),
        OptionalNamedType('attestationIdSerial', OctetString().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 713))),
        OptionalNamedType('attestationIdImei', OctetString().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 714))),
        OptionalNamedType('attestationIdMeid', OctetString().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 715))),
        OptionalNamedType('attestationIdManufacturer', OctetString().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 716))),
        OptionalNamedType('attestationIdModel', OctetString().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 717))),
        OptionalNamedType('vendorPatchLevel', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 718))),
        OptionalNamedType('bootPatchLevel', Integer().subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 719))),
    )


class KeyDescription(Sequence):
    """
    KeyDescription ::= SEQUENCE {
        keyFormat INTEGER,
        authorizationList AuthorizationList
    }
    """

    componentType = NamedTypes(
        NamedType('keyFormat', Integer()),
        NamedType('keyParams', AuthorizationList())
    )


class SecureKeyWrapper(Sequence):
    """
    SecureKeyWrapper ::= SEQUENCE {
        wrapperFormatVersion INTEGER,
        encryptedTransportKey OCTET_STRING,
        initializationVector OCTET_STRING,
        keyDescription KeyDescription,
        secureKey OCTET_STRING,
        tag OCTET_STRING
    }
    """

    componentType = NamedTypes(
        NamedType('version', Integer()),
        NamedType('encryptedTransportKey', OctetString()),
        NamedType('initializationVector', OctetString()),
        NamedType('keyDescription', KeyDescription()),
        NamedType('encryptedKey', OctetString()),
        NamedType('tag', OctetString())
    )


def encode_secure_key_wrapper(wrapper):
    return encode(wrapper)


def decode_secure_key_wrapper(data):
    return decode(data, asn1Spec=SecureKeyWrapper())
