from pysnmp.hlapi.v3arch.asyncio import *

async def run_snmp_get(ip, user, oid_numeric):
    iterator = await get_cmd(
        SnmpEngine(),
        UsmUserData(user, authProtocol = usmNoAuthProtocol, privProtocol = usmNoPrivProtocol),
        await UdpTransportTarget.create((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid_numeric))
    )

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
        

