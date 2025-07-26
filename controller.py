from pysnmp.hlapi.v3arch.asyncio import *

from pysnmp.proto.rfc1902 import (
    Integer, OctetString, IpAddress, Counter32,
    Gauge32, TimeTicks, Opaque, Counter64, Bits
)

async def run_snmp_get(
        ip, 
        user, 
        oid_numeric,
        *,
        security_level: str = "noAuthNoPriv",
        auth_key: str = None,
        priv_key: str = None,
        auth_protocol = usmNoAuthProtocol,
        priv_protocol = usmNoPrivProtocol,
):
    # Se construyen los parametros de USM segun el nivel especificado
    usm_kwargs = {}

    if security_level == "authNoPriv":
        if not auth_key:
            raise ValueError("Para authNoPriv se debe proporcionar una auth_key")
        usm_kwargs.update({
            "authKey": auth_key,
            "authProtocol": auth_protocol,
        })
    elif security_level == "authPriv":
        if not auth_key or not priv_key:
            raise ValueError("Para authPriv se debe proporcionar auth_key y priv_key")
        usm_kwargs.update({
            "authKey": auth_key,
            "authProtocol": auth_protocol,
            "privKey": priv_key,
            "privProtocol": priv_protocol,
        })

    # 3) Creación de UsmUserData
    try:
        user_data = UsmUserData(user, **usm_kwargs)
    except Exception as e:
        # Aquí te dice si alguno de los parámetros está mal
        print("[ERROR] al crear UsmUserData:", e)
        traceback.print_exc()
        raise

    # 4) Ejecución del GET
    try:
        iterator = await get_cmd(
            SnmpEngine(),
            user_data,
            await UdpTransportTarget.create((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid_numeric))
        )
        # --- DEBUG AÑADIDO ---
        errorIndication, errorStatus, errorIndex, varBinds = iterator
        print("[SNMP REPLY] errorIndication:", errorIndication)
        print("[SNMP REPLY] errorStatus:   ", errorStatus and errorStatus.prettyPrint())
        print("[SNMP REPLY] errorIndex:    ", errorIndex)
        # Si hay varBinds aunque haya error, también los muestro
        print("[SNMP REPLY] varBinds:      ", [
            (oid.prettyPrint(), val.prettyPrint()) for oid, val in varBinds or []
        ])
        # --- FIN DEBUG ---
    except Exception as e:
        print("[ERROR] fallo interno en get_cmd:", e)
        traceback.print_exc()
        raise

    errorIndication, errorStatus, errorIndex, varBinds = iterator

    if errorIndication:
        raise Exception(f"SNMP error: {errorIndication}")

    elif errorStatus:
       raise Exception(
            f"{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
        ) 

    else:
        result = []
        for varBind in varBinds:
            result.append(" = ".join([x.prettyPrint() for x in varBind]))
        return result



async def run_snmp_getnext(ip, user, oid_numeric):
    iterator = await next_cmd(
        SnmpEngine(),
        UsmUserData(user, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol),
        await UdpTransportTarget.create((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid_numeric)),
        lexicographicMode=False,  # para que solo devuelva el siguiente OID, no todo el árbol
        maxCalls=1  # para obtener solo un resultado
    )

    errorIndication, errorStatus, errorIndex, varBinds = iterator

    if errorIndication:
        raise Exception(f"SNMP error: {errorIndication}")

    elif errorStatus:
        raise Exception(
            f"{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
        )

    else:
        # Retorna el siguiente OID y su valor como lista de strings
        result = []
        for varBind in varBinds:
            result.append(" = ".join([x.prettyPrint() for x in varBind]))
        return result
        


async def run_snmp_set(ip: str, user: str, oid_numeric: str, value: str, value_type: str):
    """
    Realiza una operación SNMPv3 SET sobre un único OID.
    
    Parámetros:
        - ip: IP del dispositivo SNMP.
        - user: usuario SNMPv3 (configurado en el agente).
        - oid_numeric: cadena con el OID (ej. "1.3.6.1.2.1.1.5.0").
        - value: valor a escribir (se convierte según el tipo).
        - value_type: uno de "Integer", "OctetString", "IpAddress",
                      "Counter32", "Gauge32", "TimeTicks",
                      "Opaque", "Counter64", "Bits".
    
    Retorna:
        Lista de strings con el OID = valor resultante tras el SET.
    """
    # Mapeo de tipos string a clases pysnmp
    type_map = {
        'Integer': Integer,
        'OctetString': OctetString,
        'IpAddress': IpAddress,
        'Counter32': Counter32,
        'Gauge32': Gauge32,
        'TimeTicks': TimeTicks,
        'Opaque': Opaque,
        'Counter64': Counter64,
        'Bits': Bits
    }
    if value_type not in type_map:
        raise ValueError(f"Tipo SNMP no soportado: {value_type}")

    pysnmp_type = type_map[value_type]

    # Conversión de valor a entero si corresponde
    if pysnmp_type in (Integer, Counter32, Gauge32, TimeTicks, Counter64):
        try:
            cast_value = int(value)
        except ValueError:
            raise ValueError(f"Para {value_type} el valor debe ser un entero, se recibió: {value}")
    else:
        # OctetString, IpAddress, Opaque, Bits aceptan string directamente
        cast_value = value

    # Ejecuta el SET
    iterator = await set_cmd(
        SnmpEngine(),
        UsmUserData(user, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol),
        await UdpTransportTarget.create((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid_numeric), pysnmp_type(cast_value))
    )

    errorIndication, errorStatus, errorIndex, varBinds = iterator

    if errorIndication:
        raise Exception(f"SNMP error: {errorIndication}")
    elif errorStatus:
        raise Exception(
            f"{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex)-1][0] or '?'}"
        )
    else:
        # Devuelve lista ["OID = valor", ...]
        result = [" = ".join([x.prettyPrint() for x in varBind]) for varBind in varBinds]
        return result
