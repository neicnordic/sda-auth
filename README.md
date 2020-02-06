**Running the elixir-auth web server container**

To build the image:
```
docker build -t <image-name> <dockerfile-path>
```

Run the web server docker container as follows:
```
docker run --rm -d -p 8080:8080 <image-name>
```
