





```powershell

docker build -t testapi .
docker run -ti --rm --name TestAPI --volume ${PWD}/html:/var/www/html -p 80:80 testapi


```

