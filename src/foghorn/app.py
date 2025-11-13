from fastapi import FastAPI

app = FastAPI()


@app.get("/stats")
def read_stats():
    return {"status": "success", "data": "stats"}


@app.get("/config")
def read_config():
    return {"status": "success", "data": "config"}


@app.get("/traffic")
def read_traffic():
    return {"status": "success", "data": "traffic"}


@app.get("/logs")
def read_logs():
    return {"status": "success", "data": "logs"}
