from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd

app = FastAPI()

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# Load CSV at startup
df = pd.read_csv("q-fastapi.csv")

@app.get("/api")
def get_students(class_: list[str] = Query(default=None, alias="class")):
    """
    Returns all students or filters by class if ?class=... is provided.
    """
    data = df
    if class_:
        data = data[df["class"].isin(class_)]
    return {"students": data.to_dict(orient="records")}
