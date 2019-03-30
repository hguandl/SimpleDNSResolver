## Usage

```sh
python3 dns-v2.py
```

```sh
dig @127.0.0.1 -p 5300 github.com
; <<>> DiG 9.10.6 <<>> @127.0.0.1 -p 5300 github.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11863
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;github.com.			IN	A

;; ANSWER SECTION:
github.com.		24	IN	A	13.229.188.59
github.com.		24	IN	A	52.74.223.119
github.com.		24	IN	A	13.250.177.223

;; Query time: 10 msec
;; SERVER: 127.0.0.1#5300(127.0.0.1)
;; WHEN: Sat Mar 30 19:28:44 CST 2019
;; MSG SIZE  rcvd: 76
```

## Copyright

* 2019, Hao Guan
* 2018, Vincent Michel
