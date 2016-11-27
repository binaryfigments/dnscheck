# Go / Golang DNS and DNSSEC Check

API DNS and DNSSEC information from DNS for use as module.

For example:
```
$ ./checkdns -host=localhost -port=4004
```

# Dependencies

 * Go 1.7.x tested https://golang.org
 * govalidator https://github.com/miekg/dns
 * publixsuffix https://golang.org/x/net/publicsuffix
 * idns https://golang.org/x/net/idna

```
go get -u golang.org/x/net/idna
go get -u github.com/miekg/dns
go get -u golang.org/x/net/publicsuffix
```

# TODO

- [ ] TOP DOWN DNS CHECK!
- [ ] Error checking and reporting
- [ ] Saving data for later use
- [ ] normal **formatting**
- [ ] DNSSEC check
- [ ] Summary
- [ ] Structuring
- [ ] More information

# Download, build and run
[![asciicast](https://asciinema.org/a/94021.png)](https://asciinema.org/a/94021)

# Test with curl
[![asciicast](https://asciinema.org/a/94022.png)](https://asciinema.org/a/94022)

# Contributing

1. Fork this project
2. Create your own feature branch `git checkout -b your-new-feature`
3. Commit your changes `git commit -am 'Added some features'`
4. Push to the branch `git push origin your-new-feature`
5. Create new Pull Request

If it's prossibe, one feature at a time ;-).

# Maintainers

| Component | Contact person | Github label | Link |
|-----------|----------------|--------|---|
| Project | @binaryfigments | [comp:base] (https://github.com/binaryfigments/dnscheck/labels/core) | https://binaryfigments.com |

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