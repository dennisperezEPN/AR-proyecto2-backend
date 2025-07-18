from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from controller import run_snmp_get, run_snmp_getnext
import asyncio

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
