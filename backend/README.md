**Running the development setup**

Start the mock services located under the mock-server folder:

```bash
docker-compose up -d --force-recreate
```

And to start the backend, you may run:

```bash
pip3 install -r requirements.txt
python3 backend/route.py
```