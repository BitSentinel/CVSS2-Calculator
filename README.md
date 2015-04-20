## CVSSv2.js Calculator
CVSSv2.js is a Free and Open Source Javascript library that is based on Common Vulnerability Scoring System (CVSS) version 2.0 calculator that is based on [Common Vulnerability Scoring System Version 2 Calculator](http://nvd.nist.gov/cvss.cfm?calculator&version=2) but it's easier to share and deploy.

## How CVSS2 Algorithm Works?
> Common Vulnerability Scoring System (**CVSS**) is a free and open industry standard for assessing the severity of computer system security vulnerabilities.  It is under the custodianship of the [Forum of Incident Response and Security Teams](http://www.first.org) (FIRST).  It attempts to establish a measure of how much concern a vulnerability warrants, compared to other vulnerabilities, so efforts can be prioritized.  The scores are based on a series of measurements --called metrics-- based on expert assessment.  The scores range from 0 to 10. Vulnerabilities with a base score in the range 7.0-10.0 are **critical**, those in the range 4.0-6.9 as **major**, and 0-3.9 as **minor**.

[Wikipedia](http://en.wikipedia.org/wiki/CVSS), March 2015

For a better understanding on how CVSS works, you should read the [Complete Guide to the Common Vulnerability Scoring System Version 2.0](http://www.first.org/cvss/cvss-guide).

##Live Demo
You can see Live Demo of CVSS2.js library [here](https://bit-sentinel.com/common-vulnerability-scoring-system-cvss-2-0-online-calculator/).

##Features
* friendly charts that explain the results of any computed CVSS2 vector
* on the fly description of Basic, Temporal or Enviromental Metrics
* permalink of any vector computed using CVSSv2.js, available for sharing. Example: *http://your-url-to-calculator.com/#vector=AV:L/AC:M/Au:S/C:P/I:P/*
```javascript
CVSS2.loadVectorFromHash();
```
* function that converts vector string to object. Example: 
```javascript
CVSS2.vectorToObject("AV:A/AC:H/Au:N/C:N/I:C/A:C/E:F/RL:ND/RC:ND")
```
* function that converts CVSS2 Object to Vector. Example (please note that the object must be initiated):
```javascript
return CVSS2.objectToVector()
```


## How to Use CVSS2.js on Your Website?
* Clone this repository.
* Include all </head> files from demo/index.html in your page.
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

## For Developers
CVSSv2.js contains a lot of functions that could be used or leveraged in an updated version of this library. Please let us know about your improvements! :-)

```javascript
CVSS2.intFact = 1000; /* math helper that rounds numbers */
CVSS2.config /* main config for CVSS2 object, it contains helpers & values for computation */
CVSS2.obj  = { }; /* placeholder for computed object of any CVSS2 vector */
CVSS2.Scores = {}; /* placeholder for computed scores of the current vector */
CVSS2.vector = {}; /* placeholder for vector object */
CVSS2.resetCVSSv2Obj = function() /* create or reset the CVSS2.obj object */
CVSS2.addUnknown = function(metric) /* add any unknown XX:XX part of a vector, it will simply decide whether is Basic, Temporal or Enviromental Value */
CVSS2.removeUnknown = function(metric) /* remove any unknown XX:XX part of a vector, it will simply decide whether is Basic, Temporal or Enviromental Value */
CVSS2.getUnknown = function(metric) /* retrieves any unknown XX:XX part of a vector, it will simply decide whether is Basic, Temporal or Enviromental Value */
CVSS2.stringToMetric = function(value) /* convert a string of XX:XX into an metric object */
CVSS2.getMetricCategory = function(metric, lower) /* identify the parent of a metric, if it's not found then it throws an error */
CVSS2.getBase = function(metric) /* return a base metric */
CVSS2.getTemporal = function(metric) /* return a temporal metric */
CVSS2.getEnvironmental = function(metric) /* return an enviromental metric */
CVSS2.addBase = function(metric) /* add a base metric to the CVSS2.obj */
CVSS2.addTemporal = function(metric) /* add a temporal metric to the CVSS2.obj */
CVSS2.addEnvironmental = function(metric) /* add a enviromental metric to the CVSS2.obj */
CVSS2.removeBase = function(metric) /* remove a base metric to the CVSS2.obj */
CVSS2.removeTemporal = function(metric) /* remove a temporal metric to the CVSS2.obj */
CVSS2.removeEnvironmental = function(metric) /* remove an enviromental metric to the CVSS2.obj */
CVSS2.vectorToObject = function(vector) /* convert a string  vector to an object, if it's not possible it will throw error (s) */
CVSS2.objectToVector = function() /* convert the CVSS2 object to a vector string compatible with ANY CVSS2 calculator */
CVSS2.getFloatFromConfig = function(metric) /* return the operand value of a specific metric from config */
CVSS2.getMetricScoreFloat = function(string)  /* return the operand value of an unknown metric XX:XX from config, and generates the full object for this metric */
CVSS2.isObjectValid = function() /* basic check to see if an object is valid */
CVSS2.loadVectorFromHash = function() /* load vector from url by hash.ex : url.com/#vector=AV:L/AC:M/Au:S/C:P/I:P/ */
CVSS2.loadLabelsFromVector = function() /* function that modifies UI (labels & inputs from the page), based on a vector object - point on the HTML calculator the metrics according to the vector input */
CVSS2.computeScoresFromObject = function() /* computes baseScore, impactScore, exploitabilitySubScore, temporalScore, environmentalScore, adjustedImpactScore, adjustedTemporal, adjustedBaseScore , overallScore */
CVSS2.mkint = function(original) /* useful math function */
CVSS2.mkflt = function(original) /* useful math function */
CVSS2.quickRound = function(original) /* Rounds to 1 decimal */
CVSS2.fImpact = function (value) /* Possible values for fImpact, 0 and 1.176 */
CVSS2.computeCVSS2ScoresFromHTML = function(hook) /* convert html radio inputs in CVSS v2 vector+convert vector to object and then calculate scores */
CVSS2.computeCVSS2VectorFromHTML = function(hook) /* compute cvss2 vector from radio inputs */
CVSS2.resetHTMLInputs = function(hook) /* reset all radios */
CVSS2.generateInitialCharts = function() /* generate initial (empty) charts */
CVSS2.generateEmptyCharts = function(hook) /* generate empty charts and securely try to generate the computed charts if possible, otherwise ignore the error */
CVSS2.generateChartsFromScores = function(tmpScores) /* generate all charts based on object scores */
CVSS2.explainScore = function(score) /* explain all scores in the top-right text box */
CVSS2.replotAll = function() /* reset charts with new values */
CVSS2.addHTMLURL = function(hook) /* generate permanent url vector that can be easy to share */
CVSS2.generateEmptyCVSS2HTML = function(hook, loadbuttons) /* generate the default UI/UX (HTML) of the CVSSv2 Calculator */
```

##License
Althought CVSS2.0 is licensed under GPLv3+, it uses [jqplot](http://www.jqplot.com/) files, as well as [jQuery's](http://jquery.com).  These projects are licensed as their authors defined.
