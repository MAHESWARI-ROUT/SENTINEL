# SENTINEL: agentic, human-in-the-loop cyber-resilience POC
### run instruction
```
py -3.11 -m venv .venv
venv\Scripts\activate
pip install -r requirements.txt
python -m sentinel.demo --scenario both
python -m uvicorn sentinel.api.app:get_app --factory --port 8000
```
### in dashboard
```
open http://127.0.0.1:8000/
click run both attacks
wait for 20-30 sec
click on approve...then try rollback option
click on reject for one request
click on verify chain
click on begin only to show false alaram
```

