import threading
import asyncio
import json

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional

from controller import run_snmp_get, run_snmp_getnext, run_snmp_set

# PySNMP v3 Protocol Constants
from pysnmp.hlapi.v3arch.asyncio import (
    usmNoAuthProtocol, usmNoPrivProtocol,
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    usmDESPrivProtocol, usmAesCfb128Protocol
)

# PySNMP de bajo nivel para el listener de traps
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv

app = FastAPI()

origins = [
    "http://localhost:8080",
    "http://localhost:8000",
    "http://127.0.0.1:8080",
    # otros orígenes que necesites...
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,         # orígenes permitidos
    allow_credentials=True,
    allow_methods=["*"],           # GET, POST, PUT, etc.
    allow_headers=["*"],           # Authorization, Content-Type, etc.
)

# Mapeos para convertir strings del frontend a constantes PySNMP
AUTH_PROTOCOLS = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
}
PRIV_PROTOCOLS = {
    "DES": usmDESPrivProtocol,
    "AES": usmAesCfb128Protocol,
}

# Cola compartida y loop del evento para comunicar hilo ↔ asyncio
trap_queue: asyncio.Queue
event_loop: asyncio.AbstractEventLoop

@app.on_event("startup")
async def startup_event():
    global trap_queue, event_loop
    trap_queue = asyncio.Queue()
    # Guardamos el loop de FastAPI
    event_loop = asyncio.get_event_loop()
    # Arrancamos el listener en un hilo demonio
    t = threading.Thread(target=trap_receiver, args=(event_loop,), daemon=True)
    t.start()


def trap_receiver(loop: asyncio.AbstractEventLoop):
    """
    Se ejecuta en hilo aparte.
    Arranca el SNMP Dispatcher (asyncIO) de forma bloqueante
    y encola cada trap recibido en `trap_queue`.
    """
    # 1) Creamos un event loop para este hilo y lo asociamos
    thread_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(thread_loop)

    snmpEngine = engine.SnmpEngine()

    # SNMPv3 sin auth/priv para ejemplo y v2c "public"
    config.addV3User(
        snmpEngine,
        userName='v3user',
        authProtocol=config.usmNoAuthProtocol,
        privProtocol=config.usmNoPrivProtocol
    )
    config.addV1System(snmpEngine, 'my-area', 'public')

    # Escucha traps en UDP/162
    config.addTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpTransport().openServerMode(('0.0.0.0', 162))
    )

    def cbFun(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
        try:
            vb_list = [
                {"oid": oid.prettyPrint(), "value": val.prettyPrint()}
                for oid, val in varBinds
            ]
            trap = {
                    "timestamp": asyncio.get_event_loop().time(),
                    "source": stateReference.transportAddress[0],
                    "varBinds": vb_list
            }
            # Encolar en el loop principal SIN get_event_loop() aquí
            print("🔥 Trap recibido en Python:", trap)
            asyncio.run_coroutine_threadsafe(trap_queue.put(trap), loop) 
        except Exception as e:
            print("Error en cbFun:", e) 


    # Registra el receptor de notificaciones
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)

    # Indica al dispatcher que hay 1 trabajo activo (evita que termine)
    snmpEngine.transportDispatcher.jobStarted(1)
    # Bloquea aquí y procesa traps
    snmpEngine.transportDispatcher.runDispatcher()


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/snmp/get")
async def snmp_get(
        ip: str, 
        user: str, 
        oid: str,
        security_level: str = Query(
            "noAuthNoPriv",
            description="Nivel SNMPv3: noAuthNoPriv | authNoPriv | authPriv"
        ),
        auth_key: Optional[str] = Query(None, description="Clave de autenticación"),
        auth_protocol: str = Query("MD5", description="MD5 | SHA"),
        priv_key: Optional[str] = Query(None, description="Clave de privacidad"),
        priv_protocol: str = Query("DES", description="DES | AES"),
):
    """
    Endpoint para obtener OID via SNMPv3 asincrono.

    Parametros:
        - ip: IP del dispositivo SNMP
        - user: usuario SNMPv3
    """

    # Validaciones
    if security_level not in ("noAuthNoPriv", "authNoPriv", "authPriv"):
        raise HTTPException(400, "Nivel de seguridad inválido")
    if security_level in ("authNoPriv","authPriv") and not auth_key:
        raise HTTPException(400, "Se requiere auth_key")
    if security_level == "authPriv" and not priv_key:
        raise HTTPException(400, "Se requiere priv_key")

    # Mapear cadenas a constantes PySNMP
    auth_proto = AUTH_PROTOCOLS.get(auth_protocol, usmNoAuthProtocol)
    priv_proto = PRIV_PROTOCOLS.get(priv_protocol, usmNoPrivProtocol)

    print("parametros que se envian a la funcion run_snmp_get: ", ip, user, oid, security_level, auth_key, auth_protocol, priv_key, priv_protocol)

    try:
        if security_level == "noAuthNoPriv":
            result = await run_snmp_get(
                ip=ip,
                user=user,
                oid_numeric=oid,
                security_level=security_level,
            )
        else:
            result = await run_snmp_get(
                ip=ip,
                user=user,
                oid_numeric=oid,
                security_level=security_level,
                auth_key=auth_key,
                auth_protocol=auth_proto,
                priv_key=priv_key,
                priv_protocol=priv_proto
            )
        return {"snmp_result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 

@app.get("/snmp/getnext")
async def snmp_getnext(
        ip: str, 
        user: str, 
        oid: str,
        security_level: str = Query(
            "noAuthNoPriv",
            description="Nivel SNMPv3: noAuthNoPriv | authNoPriv | authPriv"
        ),
        auth_key: Optional[str] = Query(None, description="Clave de autenticación"),
        auth_protocol: str = Query("MD5", description="MD5 | SHA"),
        priv_key: Optional[str] = Query(None, description="Clave de privacidad"),
        priv_protocol: str = Query("DES", description="DES | AES"),
):
    # Validaciones
    if security_level not in ("noAuthNoPriv", "authNoPriv", "authPriv"):
        raise HTTPException(400, "Nivel de seguridad inválido")
    if security_level in ("authNoPriv","authPriv") and not auth_key:
        raise HTTPException(400, "Se requiere auth_key")
    if security_level == "authPriv" and not priv_key:
        raise HTTPException(400, "Se requiere priv_key")

    # Mapear cadenas a constantes PySNMP
    auth_proto = AUTH_PROTOCOLS.get(auth_protocol, usmNoAuthProtocol)
    priv_proto = PRIV_PROTOCOLS.get(priv_protocol, usmNoPrivProtocol)

    try:
        if security_level == "noAuthNoPriv":
            result = await run_snmp_getnext(
                ip=ip,
                user=user,
                oid_numeric=oid,
                security_level=security_level,
            )
        else:
            result = await run_snmp_getnext(
                ip=ip,
                user=user,
                oid_numeric=oid,
                security_level=security_level,
                auth_key=auth_key,
                auth_protocol=auth_proto,
                priv_key=priv_key,
                priv_protocol=priv_proto
            )
        return {"snmp_next_result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# --- Endpoint SNMP SET ---
class SNMPSetRequest(BaseModel):
    ip: str
    user: str
    oid: str
    value: str
    type: str   # Debe coincidir con uno de los keys de type_map en run_snmp_set
    security_level: str = Query(
        "noAuthNoPriv",
        description="Nivel SNMPv3: noAuthNoPriv | authNoPriv | authPriv"
    )
    auth_key: Optional[str] = Query(None, description="Clave de autenticación")
    auth_protocol: str = Query(
        "MD5",
        description="MD5 | SHA"
    )
    priv_key: Optional[str] = Query(None, description="Clave de privacidad")
    priv_protocol: str = Query(
        "DES",
        description="DES | AES"
    )


@app.post("/snmp/set")
async def snmp_set(req: SNMPSetRequest):
    """
    Realiza una operación SNMPv3 SET con soporte de niveles de seguridad:
    noAuthNoPriv, authNoPriv, authPriv. 
    """

    # 1) Validación del nivel de seguridad
    lvl = req.security_level
    if lvl not in ("noAuthNoPriv", "authNoPriv", "authPriv"):
        raise HTTPException(status_code=400, detail="Nivel de seguridad inválido")
    if lvl in ("authNoPriv", "authPriv") and not req.auth_key:
        raise HTTPException(status_code=400, detail="Se requiere auth_key para este nivel de seguridad")
    if lvl == "authPriv" and not req.priv_key:
        raise HTTPException(status_code=400, detail="Se requiere priv_key para authPriv")


    # 2) Mapear protocolos de cadena a constantes PySNMP
    auth_proto = AUTH_PROTOCOLS.get(req.auth_protocol, usmNoAuthProtocol)
    priv_proto = PRIV_PROTOCOLS.get(req.priv_protocol, usmNoPrivProtocol)


    # 3) Llamada a la función run_snmp_set
    try:
        if lvl == "noAuthNoPriv":
            result = await run_snmp_set(
                ip=req.ip,
                user=req.user,
                oid_numeric=req.oid,
                value=req.value,
                value_type=req.type,
                security_level=lvl
            )
        else:
            result = await run_snmp_set(
                ip=req.ip,
                user=req.user,
                oid_numeric=req.oid,
                value=req.value,
                value_type=req.type,
                security_level=lvl,
                auth_key=req.auth_key,
                auth_protocol=auth_proto,
                priv_key=req.priv_key,
                priv_protocol=priv_proto
            )
        return {"snmp_set_result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Endpoint SSE para stream de traps ---
@app.get("/traps/stream")
async def traps_stream():
    """
    SSE: emite cada trap recibido por trap_receiver() como un evento 'data:'.
    """
    async def event_generator():
        while True:
            trap = await trap_queue.get()
            # Enviar en formato SSE
            yield f"data: {json.dumps(trap)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
