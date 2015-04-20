## CVSS2.js Calculator
CVSSv2.js is a Free and Open Source Javascript library that is based on Common Vulnerability Scoring System (CVSS) version 2.0 calculator that is based on [Common Vulnerability Scoring System Version 2 Calculator](http://nvd.nist.gov/cvss.cfm?calculator&version=2).
but it easier to share and deploy.

## How CVSS2 Algorithm Works?
> Common Vulnerability Scoring System (**CVSS**) is a free and open industry standard for assessing the severity of computer system security vulnerabilities.  It is under the custodianship of the [Forum of Incident Response and Security Teams](http://www.first.org) (FIRST).  It attempts to establish a measure of how much concern a vulnerability warrants, compared to other vulnerabilities, so efforts can be prioritized.  The scores are based on a series of measurements --called metrics-- based on expert assessment.  The scores range from 0 to 10. Vulnerabilities with a base score in the range 7.0-10.0 are **critical**, those in the range 4.0-6.9 as **major**, and 0-3.9 as **minor**.

[Wikipedia](http://en.wikipedia.org/wiki/CVSS), March 2015

For a better understanding on how CVSS works, you should read the [Complete Guide to the Common Vulnerability Scoring System Version 2.0](http://www.first.org/cvss/cvss-guide).

##Live Demo
You can see Live Demo of CVSS2.js library [here](https://bit-sentinel.com/common-vulnerability-scoring-system-cvss-2-0-online-calculator/).

##Features


## How to Use CVSS2.js on Your Website?
* Clone this repository.
* Include all </head> files from demo.html in your page.
* Add HTML placeholder for your CVSS 2.0 Calculator. Example:
```html
<div id="cvss2table"> </div>
```
* Add Javascript trigger. Example:
```javascript
<script type="text/javascript">
  $(document).ready(function() { CVSS2.generateEmptyCVSS2HTML('#cvss2table');});
</script>
```
* Enjoy!

##License
Althought CVSS2.0 is licensed under GPLv3+, it uses [jqplot](http://www.jqplot.com/) files, as well as [jQuery's](http://jquery.com).  These projects are licensed as their authors defined.
