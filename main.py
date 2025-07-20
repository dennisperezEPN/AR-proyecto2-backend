import threading
import asyncio
import json

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from controller import run_snmp_get, run_snmp_getnext, run_snmp_set

# PySNMP de bajo nivel para el listener de traps
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv

app = FastAPI()

origins = [
    "http://localhost:8080",
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
async def snmp_get(ip: str, user: str, oid: str):
    """
    Endpoint para obtener OID via SNMPv3 asincrono.

    Parametros:
        - ip: IP del dispositivo SNMP
        - user: usuario SNMPv3
    """

    try:
        result = await run_snmp_get(ip, user, oid)
        return {"snmp_result": result}
    except Exception as e:
        raise HTTPException(status_code = 500, detail = str(e))


@app.get("/snmp/getnext")
async def snmp_getnext(ip: str, user: str, oid: str):
    try:
        result = await run_snmp_getnext(ip, user, oid)
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

@app.post("/snmp/set")
async def snmp_set(req: SNMPSetRequest):
    """
    Endpoint para realizar SNMPv3 SET.
    Body JSON:
    {
      "ip": "192.168.1.1",
      "user": "v3user",
      "oid": "1.3.6.1.2.1.1.5.0",
      "value": "MyDeviceName",
      "type": "OctetString"
    }
    """
    try:
        result = await run_snmp_set(req.ip, req.user, req.oid, req.value, req.type)
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
