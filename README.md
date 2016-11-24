# dnscheck

API DNS and DNSSEC information from DNS.

Download, build and run.

Usage:
```
USAGE :
  -host string
    	Set the server host (default "127.0.0.1")
  -port string
    	Set the server port (default "4004")
```

For example:
```
$ ./checkdns -host=localhost -port=4004
```

Default values are:
* Host: 127.0.0.1
* Port: 4004

When it's started, test it with curl like the command below.

```
curl http://localhost:4004/v1/domain/networking4all.com
```

Explain:
* Host and port: http://localhost:4004
* Version of test: /v1
* What to test: /domain
* Domain: networking4all.com

# Dependencies

 * Go 1.6.x tested https://golang.org
 * httprouter https://github.com/julienschmidt/httprouter
 * govalidator https://github.com/asaskevich/govalidator
 * govalidator https://github.com/miekg/dns
 * publixsuffix https://golang.org/x/net/publicsuffix

```
go get github.com/julienschmidt/httprouter
go get github.com/asaskevich/govalidator
go get github.com/miekg/dns
go get golang.org/x/net/publicsuffix
```
# TODO

- [ ] TOP DOWN DNS CHECK!
- [ ] Error checking and reporting
- [ ] Saving data for later use
- [ ] normal **formatting**
- [x] DNSSEC check
- [ ] Summary
- [ ] Structuring
- [ ] More information

# The MIT License (MIT)

Copyright (c) 2016 Sebastian Broekhoven
~~~
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
~~~