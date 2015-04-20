/* 

Author: Andrei Avadanei - CCSIR.org (2015)


Copyright: This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see http://www.gnu.org/licenses/.
Dependecies: jQuery 1.x, Bootstrap, jqplot & barRenderer, canvasAxisTickRenderer, categoryAxisRenderer, meterGaugeRenderer, pointLabels
Thanks to: FIRST.org & NIST CVSS v2.0 Calculator

Usage: 
Simply run this line in Javascript on load: CVSS2.generateEmptyCVSS2HTML('#cvss2table');
And make sure to have the following line in your HTML file, after you included all dependencies
<div id="cvss2table"> </div>

*/

var CVSS2 = {};

(function() {

	CVSS2.intFact = 1000;

	//main config for CVSS2
	CVSS2.config = {
		base: {
			title: 'Base Score Metrics',
			description: 'The base metric group captures the characteristics of a vulnerability that are constant with time and across user environments. The Access Vector, Access Complexity, and Authentication metrics capture how the vulnerability is accessed and whether or not extra conditions are required to exploit it. The three impact metrics measure how a vulnerability, if exploited, will directly affect an IT asset, where the impacts are independently defined as the degree of loss of confidentiality, integrity, and availability. For example, a vulnerability could cause a partial loss of integrity and availability, but no loss of confidentiality.',
			AV: {
				title: 'Access Vector (AV)',
				shortTitle: 'AV',
				description: 'This metric reflects how the vulnerability is exploited. The more remote an attacker can be to attack a host, the greater the vulnerability score.',
				scores: {
						L: { 
							title: 'Local',
							shortTitle: 'AV:L',
							description: 'A vulnerability exploitable with only <i>local access</i> requires the attacker to have either physical access to the vulnerable system or a local (shell) account. Examples of locally exploitable vulnerabilities are peripheral attacks such as Firewire/USB DMA attacks, and local privilege escalations (e.g., sudo).',
							score: 0.395 
						},
						A: {
							title: 'Adjacent Network',
							shortTitle: 'AV:A',
							description: 'A vulnerability exploitable with <i>adjacent network access</i> requires the attacker to have access to either the broadcast or collision domain of the vulnerable software. Examples of local networks include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment.',
							score: 0.646 
						},
						N: {
							title: 'Network',
							shortTitle: 'AV:N',
							description: 'A vulnerability exploitable with <i>network access</i> means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed “remotely exploitable”. An example of a network attack is an RPC buffer overflow.',
							score: 1 
						}
				}
			},
			AC: {
				title: 'Access Complexity (AC)',
				shortTitle: 'AC',
				description: 'This metric measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system. For example, consider a buffer overflow in an Internet service: once the target system is located, the attacker can launch an exploit at will. <br><br>  Other vulnerabilities, however, may require additional steps in order to be exploited. For example, a vulnerability in an email client is only exploited after the user downloads and opens a tainted attachment. The lower the required complexity, the higher the vulnerability score.',
				scores: {
						H: { 
							title: 'High',
							shortTitle: 'AC:H',
							description: 'Specialized access conditions exist. For example: <li>In most configurations, the attacking party must already have elevated privileges or spoof additional systems in addition to the attacking system (e.g., DNS hijacking). </li><li>The attack depends on social engineering methods that would be easily detected by knowledgeable people. For example, the victim must perform several suspicious or atypical actions. </li><li>The vulnerable configuration is seen very rarely in practice. </li><li>If a race condition exists, the window is very narrow.</li>',
							score: 0.35 
						},
						M: {
							title: 'Medium',
							shortTitle: 'AC:M',
							description: 'The access conditions are somewhat specialized; the following are examples: <li>The attacking party is limited to a group of systems or users at some level of authorization, possibly untrusted. </li><li>Some information must be gathered before a successful attack can be launched. </li><li>The affected configuration is non-default, and is not commonly configured (e.g., a vulnerability present when a server performs user account authentication via a specific scheme, but not present for another authentication scheme).</li><li>The attack requires a small amount of social engineering that might occasionally fool cautious users (e.g., phishing attacks that modify a web browser’s status bar to show a false link, having to be on someone’s “buddy” list before sending an IM exploit).</li>',
							score: 0.61 
						},
						L: {
							title: 'Low',
							shortTitle: 'AC:L',
							description: 'Specialized access conditions or extenuating circumstances do not exist. The following are examples: <li>The affected product typically requires access to a wide range of systems and users, possibly anonymous and untrusted (e.g., Internet-facing web or mail server). </li><li>The affected configuration is default or ubiquitous.  </li><li>The attack can be performed manually and requires little skill or additional information gathering.  </li><li>The \'race condition\' is a lazy one (i.e., it is technically a race but easily winnable). </li>',
							score: 0.71
						}
				}
			},
			Au: {
				title: 'Authentification (Au)',
				shortTitle: 'Au',
				description: 'This metric measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. This metric does not gauge the strength or complexity of the authentication process, only that an attacker is required to provide credentials before an exploit may occur. The possible values for this metric are listed in Table 3. The fewer authentication instances that are required, the higher the vulnerability score.<br /><br />It is important to note that the Authentication metric is different from Access Vector. Here, authentication requirements are considered <i>once the system has already been accessed</i>. Specifically, for locally exploitable vulnerabilities, this metric should only be set to \'single\' or \'multiple\' if authentication is needed beyond what is required to log into the system. An example of a locally exploitable vulnerability that requires authentication is one affecting a database engine listening on a Unix domain socket (or some other non-network interface). If the user must authenticate as a valid database user in order to exploit the vulnerability, then this metric should be set to \'single.\'',
				scores: {
						M: { 
							title: 'Multiple',
							shortTitle: 'Au:M',
							description: 'Exploiting the vulnerability requires that the attacker authenticate two or more times, even if the same credentials are used each time. An example is an attacker authenticating to an operating system in addition to providing credentials to access an application hosted on that system.',
							score: 0.45
						},
						S: {
							title: 'Single',
							shortTitle: 'Au:S',
							description: 'One instance of authentication is required to access and exploit the vulnerability.',
							score: 0.56 
						},
						N: {
							title: 'None',
							shortTitle: 'Au:N',
							description: 'Authentication is not required to access and exploit the vulnerability.',
							score: 0.704
						}
				}
			},
			C: {
				title: 'Confidentiality Impact (C)',
				shortTitle: 'C',
				description: 'This metric measures the impact on confidentiality of a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones. Increased confidentiality impact increases the vulnerability score.',
				scores: {
						N: { 
							title: 'None',
							shortTitle: 'C:N',
							description: 'There is no impact to the confidentiality of the system.',
							score: 0
						},
						P: {
							title: 'Partial',
							shortTitle: 'C:P',
							description: 'There is considerable informational disclosure. Access to some system files is possible, but the attacker does not have control over what is obtained, or the scope of the loss is constrained. An example is a vulnerability that divulges only certain tables in a database.',
							score: 0.275
						},
						C: {
							title: 'Complete',
							shortTitle: 'C:C',
							description: 'There is total information disclosure, resulting in all system files being revealed. The attacker is able to read all of the system\'s data (memory, files, etc.).',
							score: 0.660
						}
				}
			},
			I: {
				title: 'Integrity Impact (I)',
				shortTitle: 'I',
				description: 'This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and guaranteed veracity of information. Increased integrity impact increases the vulnerability score.',
				scores: {
						N: { 
							title: 'None',
							shortTitle: 'I:N',
							description: 'There is no impact to the integrity of the system.',
							score: 0
						},
						P: {
							title: 'Partial',
							shortTitle: 'I:P',
							description: 'Modification of some system files or information is possible, but the attacker does not have control over what can be modified, or the scope of what the attacker can affect is limited. For example, system or application files may be overwritten or modified, but either the attacker has no control over which files are affected or the attacker can modify files within only a limited context or scope.',
							score: 0.275
						},
						C: {
							title: 'Complete',
							shortTitle: 'I:C',
							description: 'There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised. The attacker is able to modify any files on the target system.',
							score: 0.660
						}
				}
			},
			A: {
				title: 'Availability Impact (A)',
				shortTitle: 'A',
				description: 'This metric measures the impact to availability of a successfully exploited vulnerability. Availability refers to the accessibility of information resources. Attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of a system. Increased availability impact increases the vulnerability score.',
				scores: {
						N: { 
							title: 'None',
							shortTitle: 'A:N',
							description: 'There is no impact to the availability of the system.',
							score: 0
						},
						P: {
							title: 'Partial',
							shortTitle: 'A:P',
							description: 'There is reduced performance or interruptions in resource availability. An example is a network-based flood attack that permits a limited number of successful connections to an Internet service.',
							score: 0.275
						},
						C: {
							title: 'Complete',
							shortTitle: 'A:C',
							description: 'There is a total shutdown of the affected resource. The attacker can render the resource completely unavailable.',
							score: 0.660
						}
				}
			},
		},
		temporal: {
			title: 'Temporal Score Metrics',
			description: 'The threat posed by a vulnerability may change over time. Three such factors that CVSS captures are: confirmation of the technical details of a vulnerability, the remediation status of the vulnerability, and the availability of exploit code or techniques. Since temporal metrics are optional they each include a metric value that has no effect on the score. This value is used when the user feels the particular metric does not apply and wishes to "skip over" it.',
			E: {
				title: 'Exploitability (E)',
				shortTitle: 'E',
				description: 'This metric measures the current state of exploit techniques or code availability. Public availability of easy-to-use exploit code increases the number of potential attackers by including those who are unskilled, thereby increasing the severity of the vulnerability. <br /><br /> Initially, real-world exploitation may only be theoretical. Publication of proof of concept code, functional exploit code, or sufficient technical details necessary to exploit the vulnerability may follow. Furthermore, the exploit code available may progress from a proof-of-concept demonstration to exploit code that is successful in exploiting the vulnerability consistently. In severe cases, it may be delivered as the payload of a network-based worm or virus. The more easily a vulnerability can be exploited, the higher the vulnerability score.',
				scores: {
						ND: { 
							title: 'Not Defined',
							shortTitle: 'E:ND',
							description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.',
							score: 1.0
						},
						U: {
							title: 'Unproven that exploit exists',
							shortTitle: 'E:U',
							description: 'No exploit code is available, or an exploit is entirely theoretical.',
							score: 0.85
						},
						POC: {
							title: 'Proof of concept code',
							shortTitle: 'E:POC',
							description: 'Proof-of-concept exploit code or an attack demonstration that is not practical for most systems is available. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.',
							score: 0.9
						},
						F: {
							title: 'Functional exploit exists',
							shortTitle: 'E:F',
							description: 'Functional exploit code is available. The code works in most situations where the vulnerability exists.',
							score: 0.95
						},
						H: {
							title: 'High',
							shortTitle: 'E:H',
							description: 'Either the vulnerability is exploitable by functional mobile autonomous code, or no exploit is required (manual trigger) and details are widely available. The code works in every situation, or is actively being delivered via a mobile autonomous agent (such as a worm or virus).',
							score: 1.0
						},
				}
			},
			RL: {
				title: 'Remediation Level (RL)',
				shortTitle: 'RL',
				description: 'The remediation level of a vulnerability is an important factor for prioritization. The typical vulnerability is unpatched when initially published. Workarounds or hotfixes may offer interim remediation until an official patch or upgrade is issued. Each of these respective stages adjusts the temporal score downwards, reflecting the decreasing urgency as remediation becomes final. The less official and permanent a fix, the higher the vulnerability score is.',
				scores: {
						ND: { 
							title: 'Not Defined',
							shortTitle: 'RL:ND',
							description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.',
							score: 1.0
						},
						OF: {
							title: 'Official Fix',
							shortTitle: 'RL:OF',
							description: 'A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.',
							score: 0.87
						},
						TF: {
							title: 'Temporary Fix',
							shortTitle: 'RL:TF',
							description: 'There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.',
							score: 0.9
						},
						W: {
							title: 'Workaround',
							shortTitle: 'RL:W',
							description: 'There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.',
							score: 0.95
						},
						U: {
							title: 'Unavailable',
							shortTitle: 'RL:U',
							description: 'There is either no solution available or it is impossible to apply.',
							score: 1.0
						},
				}
			},
			RC: {
				title: 'Report Confidence (RC)',
				shortTitle: 'RC',
				description: 'This metric measures the degree of confidence in the existence of the vulnerability and the credibility of the known technical details. Sometimes, only the existence of vulnerabilities are publicized, but without specific details. The vulnerability may later be corroborated and then confirmed through acknowledgement by the author or vendor of the affected technology. The urgency of a vulnerability is higher when a vulnerability is known to exist with certainty. This metric also suggests the level of technical knowledge available to would-be attackers.  The more a vulnerability is validated by the vendor or other reputable sources, the higher the score.',
				scores: {
						ND: { 
							title: 'Not Defined',
							shortTitle: 'RC:ND',
							description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.',
							score: 1.0
						},
						UC: {
							title: 'Unconfirmed',
							shortTitle: 'RC:UC',
							description: 'There is a single unconfirmed source or possibly multiple conflicting reports. There is little confidence in the validity of the reports. An example is a rumor that surfaces from the hacker underground.',
							score: 0.9
						},
						UR: {
							title: 'Uncorroborated',
							shortTitle: 'RC:UR',
							description: 'There are multiple non-official sources, possibly including independent security companies or research organizations. At this point there may be conflicting technical details or some other lingering ambiguity.',
							score: 0.95
						},
						C: {
							title: 'Confirmed',
							shortTitle: 'RC:C',
							description: 'The vulnerability has been acknowledged by the vendor or author of the affected technology. The vulnerability may also be "Confirmed: when its existence is confirmed from an external event such as publication of functional or proof-ofconcept exploit code or widespread exploitation.',
							score: 1.0
						}
				}
			},
		},
		environmental: {
			title: 'Environmental Score Metrics',
			description: 'Different environments can have an immense bearing on the risk that a vulnerability poses to an organization and its stakeholders. The CVSS environmental metric group captures the characteristics of a vulnerability that are associated with a user\'s IT environment. Since environmental metrics are optional they each include a metric value that has no effect on the score. This value is used when the user feels the particular metric does not apply and wishes to \'skip over\' it.',
			CDP: {
				title: 'Collateral Damage Potential (CDP)',
				shortTitle: 'CDP',
				description: 'This metric measures the potential for loss of life or physical assets through damage or theft of property or equipment. The metric may also measure economic loss of productivity or revenue. Naturally, the greater the damage potential, the higher the vulnerability score. ',
				scores: {
						ND: { 
							title: 'Not Defined',
							shortTitle: 'CDP:ND',
							description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.',
							score: 0
						},
						N: {
							title: 'None',
							shortTitle: 'CDP:N',
							description: 'There is no potential for loss of life, physical assets, productivity or revenue.',
							score: 0
						},
						L: {
							title: 'Low (light loss)',
							shortTitle: 'CDP:L',
							description: 'A successful exploit of this vulnerability may result in slight physical or property damage. Or, there may be a slight loss of revenue or productivity to the organization.',
							score: 0.1
						},
						LM: {
							title: 'Low-Medium',
							shortTitle: 'CDP:LM',
							description: 'A successful exploit of this vulnerability may result in moderate physical or property damage. Or, there may be a moderate loss of revenue or productivity to the organization.',
							score: 0.3
						},
						MH: {
							title: 'Medium-High',
							shortTitle: 'CDP:MH',
							description: 'A successful exploit of this vulnerability may result in significant physical or property damage or loss. Or, there may be a significant loss of revenue or productivity.',
							score: 0.4
						},
						H: {
							title: 'High (catastrophic loss)',
							shortTitle: 'CDP:H',
							description: 'A successful exploit of this vulnerability may result in catastrophic physical or property damage and loss. Or, there may be a catastrophic loss of revenue or productivity.',
							score: 0.5
						}
				}
			},
			TD: {
				title: 'Target Distribution (TD)',
				shortTitle: 'TD',
				description: 'This metric measures the proportion of vulnerable systems. It is meant as an environment-specific indicator in order to approximate the percentage of systems that could be affected by the vulnerability. The possible values for this metric are listed in Table 11. The greater the proportion of vulnerable systems, the higher the score.',
				scores: {
						ND: { 
							title: 'Not Defined',
							shortTitle: 'TD:ND',
							description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric. ',
							score: 1.0
						},
						N: {
							title: 'None [0%]',
							shortTitle: 'TD:N',
							description: 'No target systems exist, or targets are so highly specialized that they only exist in a laboratory setting. Effectively 0% of the environment is at risk.',
							score: 0
						},
						L: {
							title: 'Low [0-25%]',
							shortTitle: 'TD:L',
							description: 'Targets exist inside the environment, but on a small scale. Between 1% - 25% of the total environment is at risk.',
							score: 0.25
						},
						M: {
							title: 'Medium [26-75%]',
							shortTitle: 'TD:M',
							description: 'Targets exist inside the environment, but on a medium scale. Between 26% - 75% of the total environment is at risk.',
							score: 0.75
						},
						H: {
							title: 'High [76-100%]',
							shortTitle: 'TD:H',
							description: 'Targets exist inside the environment on a considerable scale. Between 76% - 100% of the total environment is considered at risk.',
							score: 1.0
						}
				}
			},
			CR: {
				title: 'Confidentiality Requirement (CR)',
				shortTitle: 'CR',
				description: 'This metric enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a user’s organization, measured in terms of confidentiality, integrity, and availability, That is, if an IT asset supports a business function for which availability is most important, the analyst can assign a greater value to availability, relative to confidentiality and integrity. ',
				scores: {
						ND: { 
							title: 'Not Defined',
							shortTitle: 'CR:ND',
							description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.',
							score: 1.0
						},
						L: {
							title: 'Low',
							shortTitle: 'CR:L',
							description: 'Loss of Confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).',
							score: 0.5
						},
						M: {
							title: 'Medium',
							shortTitle: 'CR:M',
							description: 'Loss of Confidentiality is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).',
							score: 1.0
						},
						H: {
							title: 'High',
							shortTitle: 'CR:H',
							description: 'Loss of Confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).',
							score: 1.51
						}
				}
			},
			IR: {
				title: 'Integrity Requirement (IR)',
				shortTitle: 'IR',
				description: 'This metric enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a user’s organization, measured in terms of confidentiality, integrity, and availability, That is, if an IT asset supports a business function for which availability is most important, the analyst can assign a greater value to availability, relative to confidentiality and integrity. ',
				scores: {
						ND: { 
							title: 'Not Defined',
							shortTitle: 'IR:ND',
							description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.',
							score: 1.0
						},
						L: {
							title: 'Low',
							shortTitle: 'IR:L',
							description: ' Loss of Integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).',
							score: 0.5
						},
						M: {
							title: 'Medium',
							shortTitle: 'IR:M',
							description: 'Loss of Integrity is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).',
							score: 1.0
						},
						H: {
							title: 'High',
							shortTitle: 'IR:H',
							description: 'Loss of Integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).',
							score: 1.51
						}
				}
			},
			AR: {
				title: 'Availability Requirement (AR)',
				shortTitle: 'AR',
				description: 'This metric enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a user’s organization, measured in terms of confidentiality, integrity, and availability, That is, if an IT asset supports a business function for which availability is most important, the analyst can assign a greater value to availability, relative to confidentiality and integrity. ',
				scores: {
						ND: { 
							title: 'Not Defined',
							shortTitle: 'AR:ND',
							description: 'Assigning this value to the metric will not influence the score. It is a signal to the equation to skip this metric.',
							score: 1.0
						},
						L: {
							title: 'Low',
							shortTitle: 'AR:L',
							description: 'Loss of availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).',
							score: 0.5
						},
						M: {
							title: 'Medium',
							shortTitle: 'AR:M',
							description: 'Loss of availability is likely to have a serious adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).',
							score: 1.0
						},
						H: {
							title: 'High',
							shortTitle: 'AR:H',
							description: 'Loss of availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).',
							score: 1.51
						}
				}
			},
		}

	};
	
	CVSS2.obj  = { };
	CVSS2.Scores = {};
	CVSS2.vector = {};

	//get basic CVSS2 obj
	CVSS2.resetCVSSv2Obj = function() {
		var obj = { base: {}, temporal: {}, environmental: {} };


		return obj;
	}

	//add unknown metric, it might be: base, temporal, env
	CVSS2.addUnknown = function(metric) { this['add' + this.getMetricCategory(metric)](metric); }

	//remove unknown metric, it might be: base, temporal, env
	CVSS2.removeUnknown = function(metric) { this['remove' + this.getMetricCategory(metric)](metric); }

	//get unknown metric, it might be: base, temporal, env
	CVSS2.getUnknown = function(metric) { 
		var ret = this['get' + this.getMetricCategory(metric)](metric); 
		return (ret != null?ret:false);
	}

	//string must have the format of "VECTOR:VALUE"
	CVSS2.stringToMetric = function(value) { 
		if(value.indexOf(':') != -1) {
			value = value.split(':');

			return { name: value[0], val: value[1] };
		} else {
			return { name: value };
		}
	}

	//search a metric in all categories, otherwise throw error
	CVSS2.getMetricCategory = function(metric, lower) {
		if(lower == null) lower = false;

		if(typeof this.config.base[metric.name] == 'object') return lower?'base':'Base';
		if(typeof this.config.temporal[metric.name] == 'object') return lower?'temporal':'Temporal';
		if(typeof this.config.environmental[metric.name] == 'object') return lower?'environmental':'Environmental';

		throw "Invalid Search Metric Category input.";
	}

	//some useful functions, easy as hell
	CVSS2.getBase = function(metric) { return this.obj.base[metric.name] }

	CVSS2.getTemporal = function(metric) { return this.obj.temporal[metric.name] }

	CVSS2.getEnvironmental = function(metric) { return this.obj.environmental[metric.name] }

	CVSS2.addBase = function(metric) { this.obj.base[metric.name] = metric.val; }

	CVSS2.addTemporal = function(metric) { this.obj.temporal[metric.name] = metric.val; }

	CVSS2.addEnvironmental = function(metric) { this.obj.environmental[metric.name] = metric.val; }

	CVSS2.removeBase = function(metric) { this.obj.base[metric.name] = false; }

	CVSS2.removeTemporal = function(metric) { this.obj.temporal[metric.name] = false; }

	CVSS2.removeEnvironmental = function(metric) { this.obj.environmental[metric.name] = false; }

	//EX: AV:A/AC:H/Au:N/C:N/I:C/A:C/E:F/RL:ND/RC:ND
	CVSS2.vectorToObject = function(vector) {
		this.vector = vector;

		if(!vector.length || vector.indexOf('/') == -1)
			throw 'Invalid string.';
		vector = vector.split('/');
		
		this.obj = this.resetCVSSv2Obj(); 
		for(var i=0; i<vector.length;i++) {
			var metric = this.stringToMetric(vector[i]);
			this.addUnknown(metric); 
		}

		return this.obj;
	}

	// return something like: AV:A/AC:H/Au:N/C:N/I:C/A:C/E:F/RL:ND/RC:ND
	CVSS2.objectToVector = function() {
		var vector = '';

		///add base
		for(var key in this.obj.base) {
			if(this.obj.base.hasOwnProperty(key)) {
				vector += key+':'+this.obj.base[key] + '/';
			}
		}

		for(var key in this.obj.temporal) {
			if(this.obj.temporal.hasOwnProperty(key)) {
				if(this.obj.temporal[key] == 'ND') // Not Defined
					continue;
				vector += key+':'+this.obj.temporal[key] + '/';
			}
		}

		for(var key in this.obj.environmental) {
			if(this.obj.environmental.hasOwnProperty(key)) {
				if(this.obj.environmental[key] == 'ND') // Not Defined
					continue;
				vector += key+':'+this.obj.environmental[key] + '/';
			}
		}

		this.vector = vector.slice(0,-1);
		return this.vector;
	}

	//helper for getting the value from config
	CVSS2.getFloatFromConfig = function(metric) {
		return this.config[metric.category][metric.name].scores[metric.val].score;
	}

	//generate object and return float value from config based on a string. it takes care of temporal and env
	CVSS2.getMetricScoreFloat = function(string) {
		var metric       = this.stringToMetric(string);
		metric.val       = this.getUnknown(metric);
		metric.category  = this.getMetricCategory(metric, true);

 		if(metric.val == false || typeof metric.val == 'undefined') {
			if(metric.category == 'temporal' || metric.category == 'environmental') {
				metric.val = 'ND'; //Not Defined
				return this.getFloatFromConfig(metric);
			}
			throw 'Please fill in all base score metrics in order to generate a score!';
		}

		return this.getFloatFromConfig(metric);
	}

	//basic check to see if an object is valid
	CVSS2.isObjectValid = function() {
		if(!('base' in this.obj))
			throw 'Invalid Base Object';

		for(var key in this.config.base) {
			if(!this.config.base.hasOwnProperty(key)) continue;
			if(key == 'title') continue;
			if(key == 'description') continue;

			if(!(key in this.obj.base))
				throw 'Invalid Base Metrics';
		}
	}
	
	//load vector from url by hash.ex : url.com/#vector=AV:L/AC:M/Au:S/C:P/I:P/
	CVSS2.loadVectorFromHash = function() {
		var hash = window.location.hash.substr(1);
		if(hash.indexOf('&') != -1) {
			hash = hash.split('&');
		} else {
			hash = [hash];
		}

		for(var h in hash) {
			if(hash[h].indexOf('=') == -1) continue;

			hash[h] = hash[h].split('=');
			if(hash[h][0] != 'vector') continue;

			if(hash[h][1].length == 0) continue;

			this.vectorToObject(hash[h][1]);
			this.computeScoresFromObject();
			this.generateChartsFromScores();
		}
	}

	//point on the HTML calculator the metrics according to the vector input
	CVSS2.loadLabelsFromVector = function() {
		if(this.vector.length == 0 )
			throw 'Invalid vector';
		var vectors = this.vector.split('/');

		for(var key in vectors) {
			$('#lbl'+vectors[key].replace(':','_')).click();
		}
	}

	//computes the scores based on the internal object of CVSS2
	CVSS2.computeScoresFromObject = function() {
		//todo validate object to see if every base value scores are set

		this.Scores = {
			baseScore : -1,
			impactScore : 0,
			exploitabilitySubScore : 0,
			temporalScore: -1,
			environmentalScore: -1,
			adjustedImpactScore : 0,
			adjustedTemporal : 0,
			adjustedBaseScore : 0,
			overallScore : -1,
		};

		//check if base object is valid and has all the info required initialized
		this.isObjectValid();

		// Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
		this.Scores.impactScore = 10.41 * this.mkflt(this.mkint(1.0) - this.mkint(this.mkflt(this.mkint(1.0) - this.mkint(this.getMetricScoreFloat('C'))) * this.mkflt(this.mkint(1.0) - this.mkint(this.getMetricScoreFloat('I'))) * this.mkflt(this.mkint(1.0) - this.mkint(this.getMetricScoreFloat('A')))));
		
		// Exploitability = 20* AccessVector*AccessComplexity*Authentication
		this.Scores.exploitabilitySubScore = 20.0 * this.getMetricScoreFloat('AC') * this.getMetricScoreFloat('Au') * this.getMetricScoreFloat('AV');

		// BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
  		// where f(impact)= 0 if Impact=0, 1.176 otherwise
		
  		this.Scores.baseScore = this.quickRound(this.mkflt(this.mkint(0.6 * this.Scores.impactScore) + this.mkint(0.4 * this.Scores.exploitabilitySubScore) - this.mkint(1.5)) * this.fImpact(this.Scores.impactScore));

  		/* Only calculating Temporal if an option was chose */
  		
  		if(this.getTemporal({name:'E'}) || this.getTemporal({name:'RL'}) || this.getTemporal({name:'RC'})) {
  			// TemporalScore = round_to_1_decimal( BaseScore * Exploitability * RemediationLevel * ReportConfidence )
    		this.Scores.temporalScore = this.quickRound(this.Scores.baseScore * this.getMetricScoreFloat('E') * this.getMetricScoreFloat('RL') * this.getMetricScoreFloat('RC'));
  		}

  		/* Only calculating Environmental if an option was chose */
  		if(this.getEnvironmental({name:'CDP'}) || this.getEnvironmental({name:'TD'}) || this.getEnvironmental({name:'CR'}) || this.getEnvironmental({name:'IR'}) || this.getEnvironmental({name:'AR'})) {
  			
			//AdjustedImpact = Min(10, 10.41 * (1 - (1 - ConfImpact * ConfReq) * (1 - IntegImpact * IntegReq) * (1 - AvailImpact * AvailReq)))
			this.Scores.adjustedImpactScore = Math.min(10, 10.41 * this.mkflt(this.mkint(1.0) - this.mkint(this.mkflt(this.mkint(1.0) - this.mkint(this.getMetricScoreFloat('C') * this.getMetricScoreFloat('CR'))) * (this.mkflt(this.mkint(1.0) - this.mkint(this.getMetricScoreFloat('I') * this.getMetricScoreFloat('IR'))) * this.mkflt(this.mkint(1.0) - this.mkint(this.getMetricScoreFloat('A') * this.getMetricScoreFloat('AR')))))));

			// AdjustedBaseScore = quickRound((0.6 * AdjustedImpact + 0.4 * Exploitability - 1.5) * f(Impact))
			this.Scores.adjustedBaseScore = this.quickRound(this.mkflt(this.mkint(0.6 * this.Scores.adjustedImpactScore) + this.mkint(0.4 * this.Scores.exploitabilitySubScore) - this.mkint(1.5)) * this.fImpact(this.Scores.impactScore));

			// AdjustedTemporal = TemporalScore recomputed with the BaseScore's Impact sub-equation replaced with the AdjustedImpact equation
			// AdjustedTemporal = quickRound(AdjustedBaseScore * Exploitability * RemediationLevel * ReportConfidence)
			this.Scores.adjustedTemporal = this.quickRound(this.Scores.adjustedBaseScore * this.getMetricScoreFloat('E') * this.getMetricScoreFloat('RL') * this.getMetricScoreFloat('RC'));

			//EnvironmentalScore = quickRound((AdjustedTemporal + (10 - AdjustedTemporal) * CollateralDamagePotential) * TargetDistribution) 
			this.Scores.environmentalScore = this.quickRound(this.mkflt(this.mkint(this.Scores.adjustedTemporal) + this.mkint(this.mkflt(this.mkint(10) - this.mkint(this.Scores.adjustedTemporal)) * this.getMetricScoreFloat('CDP'))) * this.getMetricScoreFloat('TD'));
		}

		/* 
			Overall CVSS Score is something imported from NVD and it just takes the 
			most defined score. If there is no Environmental or Temporal score defined but 
			there is a Base Score then the Overall Score is the Base Score. If the 
			Environmental Score is defined then the Overall Score will be the 
			Environmental Score otherwise if only the Temporal Score is 
			defined then the Overall Score will be the Temporal Score.
		*/

		if (this.Scores.baseScore >= 0) {

			this.Scores.overallScore = this.Scores.baseScore;
			if (this.Scores.environmentalScore >= 0) {
				this.Scores.overallScore = this.Scores.environmentalScore;
			} else if (this.Scores.temporalScore >= 0) {
				this.Scores.overallScore = this.Scores.temporalScore;
			}
		}
		 
		for(var score in this.Scores) {
			this.Scores[score] = this.quickRound(this.Scores[score]);
		}
		 

		return this.Scores;
	}

	//useful math functions
	CVSS2.mkint = function(original) {
		return Math.round(original * this.intFact);
	}

	CVSS2.mkflt = function(original) {
	  return original / this.intFact;
	}

	/* Rounds to 1 decimal */
	CVSS2.quickRound = function(original) {
	  return Math.round(original * 10) / 10;
	}

	/* Possible values for fImpact, 0 and 1.176  */
	CVSS2.fImpact = function (value) {
	  if (value > 0) {
	    return 1.176;
	  } else {
	    return 0;
	  }
	}

	//convert html radio inputs in CVSS v2 vector+convert vector to object and then computes scores
	CVSS2.computeCVSS2ScoresFromHTML = function(hook) {
		this.vector = this.computeCVSS2VectorFromHTML(hook);
		this.vectorToObject(this.vector);
		return this.computeScoresFromObject();
	}

	//compute cvss2 vector from radio inputs
	CVSS2.computeCVSS2VectorFromHTML = function(hook) {
		var vector = '';
		
		$(hook + ' input:radio').each(function() {
			if($(this).attr('checked')) {
				id = $(this).attr('id');
				id = id.split('_');
				if(id[1] != 'ND')
					vector += $(this).attr('id').replace('_',':') + '/';
			}
		});
		this.vector = vector.slice(0,-1);
		return this.vector;
	}

	/* HTML CVSS v2 API - UI+UX based on Bootstrap 3 + $ 1.x */

	//reset all radios
	CVSS2.resetHTMLInputs = function(hook) {
		$(hook + ' input:radio').each(function() {
			if($(this).attr('checked')) {
				$(this).attr('checked',false);
			}
		});

		$(hook + ' label.btn-primary').removeClass('btn-primary').addClass('btn-default');

		$('#lblE_ND').click();
		$('#lblRL_ND').click();
		$('#lblRC_ND').click();
		$('#lblCDP_ND').click();
		$('#lblTD_ND').click();
		$('#lblCR_ND').click();
		$('#lblIR_ND').click();
		$('#lblAR_ND').click();
	}

	//generate initial chars
	CVSS2.generateInitialCharts = function() {
		  // Specify a custom tick Array.
	      var yTicks = [0, 2, 4, 6, 8, 10];

	     // Speed at which the chart is animated
	     var chartAnimationSpeed = 1200;

		//init
		var baseScores = [
			[
				['Base', 0],
				['Impact', 0],
				['Exploitability', 0]
			]
		];

		var temporalScores = [
			[
				['Temporal', 0]
			]
		];

		var environmentalScores = [
			[
				['Environmental', 0],
				['Modified Impact', 0]
			]
		];

		var overallScore = [
			[
				['Overall', 0]
			]
		];
		  // Creating the base scores chart
		  CVSS2.basePlot = $.jqplot('cvss-base-scores-chart', baseScores, {
		    animate: true,
		    animateReplot: true,
		    title: {
		      text: 'Base Scores',
		      fontSize: '12pt'
		    },
		    seriesColors: ['#7EBE18', '#7EBE18', '#7EBE18', '#1D61A4', '#EF9E00', '#D1410B'],
		    seriesDefaults: {
		      renderer: $.jqplot.BarRenderer,
		      rendererOptions: {
		        varyBarColor: true,
		        animation: {
		          speed: chartAnimationSpeed
		        }
		      },
		      pointLabels: {
		        show: true,
		        location: 's',
		        edgeTolerance: -15
		      }
		    },
		    axes: {
		      xaxis: {
		        renderer: $.jqplot.CategoryAxisRenderer
		      },
		      yaxis: {
		        min: 0,
		        max: 10,
		        ticks: yTicks
		      }
		    }
		  });

		  // Creating the temporal score chart
		  CVSS2.temporalPlot = $.jqplot('cvss-temporal-score-chart', temporalScores, {
		    animate: true,
		    animateReplot: true,
		    title: {
		      text: 'Temporal',
		      fontSize: '12pt'
		    },
		    seriesColors: ['#59ACCF'],
		    seriesDefaults: {
		      renderer: $.jqplot.BarRenderer,
		      rendererOptions: {
		        varyBarColor: true,
		        animation: {
		          speed: chartAnimationSpeed
		        }
		      },
		      pointLabels: {
		        show: true,
		        location: 's',
		        edgeTolerance: -15
		      }
		    },
		    axes: {
		      xaxis: {
		        renderer: $.jqplot.CategoryAxisRenderer
		      },
		      yaxis: {
		        min: 0,
		        max: 10,
		        ticks: yTicks
		      }
		    }
		  });

		  // Environmental score
		  CVSS2.environmentalPlot = $.jqplot('cvss-environmental-score-chart', environmentalScores, {
		    animate: true,
		    animateReplot: true,
		    title: {
		      text: 'Environmental',
		      fontSize: '12pt'
		    },
		    seriesColors: ['#EF9E00', '#FFC54D'],
		    seriesDefaults: {
		      renderer: $.jqplot.BarRenderer,
		      rendererOptions: {
		        varyBarColor: true,
		        animation: {
		          speed: chartAnimationSpeed
		        }
		      },
		      pointLabels: {
		        show: true,
		        location: 's',
		        edgeTolerance: -12
		      }
		    },
		    axes: {
		      xaxis: {
		        renderer: $.jqplot.CategoryAxisRenderer
		      },
		      yaxis: {
		        min: 0,
		        max: 10,
		        ticks: yTicks
		      }
		    }
		  });

		  // Overall chart
		  CVSS2.overallPlot = $.jqplot('cvss-overall-score-chart', overallScore, {
		    animate: true,
		    animateReplot: true,
		    title: {
		      text: 'Overall',
		      fontSize: '12pt'
		    },
		    seriesColors: ['#66cc66'],
		    seriesDefaults: {
		      renderer: $.jqplot.BarRenderer,
		      rendererOptions: {
		        varyBarColor: true,
		        animation: {
		          speed: chartAnimationSpeed
		        }
		      },
		      pointLabels: {
		        show: true,
		        location: 's',
		        edgeTolerance: -15
		      }
		    },
		    axes: {
		      xaxis: {
		        renderer: $.jqplot.CategoryAxisRenderer
		      },
		      yaxis: {
		        min: 0,
		        max: 10,
		        ticks: yTicks
		      }
		    }
		  });
	}

	//other HTML helpful function
	CVSS2.generateEmptyCharts = function(hook) {
		$('<div id="cvss-charts-container"><div id="cvss-base-scores-chart"></div><div id="cvss-temporal-score-chart"></div><div id="cvss-environmental-score-chart"></div><div id="cvss-overall-score-chart"></div><div id="cvss-text-score-container"><div class="score-row major-score"><div class="score-cell">CVSS Base Score</div><div class="score-cell" id="cvss-base-score-cell">Undefined</div></div><div class="score-row"><div class="score-cell">Impact Subscore</div><div class="score-cell" id="cvss-impact-score-cell">Undefined</div></div><div class="score-row"><div class="score-cell">Exploitability Subscore</div><div class="score-cell" id="cvss-exploitability-score-cell">Undefined</div></div><div class="score-row major-score"><div class="score-cell">CVSS Temporal Score</div><div class="score-cell" id="cvss-temporal-score-cell">Not Defined</div></div><div class="score-row major-score"><div class="score-cell">CVSS Environmental Score</div><div class="score-cell" id="cvss-environmental-score-cell">Not Defined</div></div><div class="score-row"><div class="score-cell">Modified Impact Subscore</div><div class="score-cell" id="cvss-mod-impact-score-cell">Not Defined</div></div><div class="score-row major-score"><div class="score-cell">Overall CVSS Score</div><div class="score-cell" id="cvss-overall-score-cell">Not Defined</div></div></div></div>').appendTo(hook);
		this.generateInitialCharts();
		try {
			this.computeScoresFromObject();
		} catch(err) {}
	}

	//generate all charts based on object scores
	CVSS2.generateChartsFromScores = function(tmpScores) {

		if(tmpScores == null)
			var tmpScores = Object.create(this.Scores);

		baseScores = [
			[
			  ['Base', tmpScores.baseScore],
			  ['Impact', tmpScores.impactScore],
			  ['Exploitability', tmpScores.exploitabilitySubScore]
			]
		];

		this.basePlot.replot({
			data: baseScores
		});

		temporalScores = [
			[
			  ['Temporal', tmpScores.temporalScore]
			]
		];
		this.temporalPlot.replot({
			data: temporalScores
		});

		environmentalScores = [
			[
			  ['Environmental', tmpScores.environmentalScore],
			  ['Modified Impact', tmpScores.adjustedImpactScore]
			]
		];

		this.environmentalPlot.replot({
			data: environmentalScores
		});

		overallScore = [
			[
			  ['Overall', tmpScores.overallScore]
			]
		];
		this.overallPlot.replot({
			data: overallScore
		});

		
		/* Updating Text Scores */
		if (typeof tmpScores.baseScore == 'undefined' || tmpScores.baseScore < 0) {
			tmpScores.baseScore = "Not Defined";
		}
		if (typeof tmpScores.impactScore == 'undefined' || tmpScores.impactScore < 0) {
			tmpScores.impactScore = "Not Defined";
		}
		if (typeof tmpScores.exploitabilitySubScore == 'undefined' || tmpScores.exploitabilitySubScore < 0) {
			tmpScores.exploitabilitySubScore = "Not Defined";
		}
		if (typeof tmpScores.temporalScore == 'undefined' || tmpScores.temporalScore < 0) {
			tmpScores.temporalScore = "Not Defined";
		}
		if (typeof tmpScores.environmentalScore == 'undefined' || tmpScores.environmentalScore < 0) {
			tmpScores.environmentalScore = "Not Defined";
		}
		if (typeof tmpScores.adjustedImpactScore == 'undefined' || tmpScores.adjustedImpactScore < 0) {
			tmpScores.adjustedImpactScore = "Not Defined";
		}
		if (typeof tmpScores.overallScore == 'undefined' || tmpScores.overallScore < 0) {
			tmpScores.overallScore = "Not Defined";
		}

		$("#cvss-base-score-cell").text(tmpScores.baseScore);
		$("#cvss-impact-score-cell").text(tmpScores.impactScore);
		$("#cvss-exploitability-score-cell").text(tmpScores.exploitabilitySubScore);
		$("#cvss-temporal-score-cell").text(tmpScores.temporalScore);
		$("#cvss-environmental-score-cell").text(tmpScores.environmentalScore);
		$("#cvss-mod-impact-score-cell").text(tmpScores.adjustedImpactScore);
		$("#cvss-overall-score-cell").text(tmpScores.overallScore);

	}

	CVSS2.explainScore = function(score) {
		if(typeof score == 'undefined' || score == null || score < 0)
			return 'Not Defined';

		if(score <= 3.9) 
			return score + ' (Low)';
		if(score <= 6.9)
			return score + ' (Medium)';
		if(score <= 8.9)
			return score + ' (High)';
		if(score <= 10)
			return score + ' (Critical)';
	}

	CVSS2.replotAll = function() {
		this.basePlot.replot();
		this.temporalPlot.replot();
		this.environmentalPlot.replot();
		this.overallPlot.replot();
	}
	
	//url generator for hashed vector
	CVSS2.addHTMLURL = function(hook) {
		$(hook + ' .vector_url').html('<a data-toggle="tooltip" data-placement="top" title="Share CVSS v2 Vector. You can copy this URL and share with others." href="#vector='+this.vector+'">'+this.vector+'</a>')
	}

	//generate default HTML calculator
	CVSS2.generateEmptyCVSS2HTML = function(hook, loadbuttons) {
		var base = this.config.base;
		var temporal = this.config.temporal;
		var environmental = this.config.environmental;

		if(loadbuttons == null) loadbuttons = true;

		//add charts
		this.generateEmptyCharts(hook);

		$('<div class="vector_url" align="center">None</div>').appendTo(hook);

		//generate base html
		var basehtml = '<div class="cvss2-base-form"><label class="title" data-placement="top" data-toggle="tooltip" title="'+base.description+'">- '+base.title+'</label>';
		basehtml += '<div class="clearfix"></div><div class="cvss2-base-inner">';

		for(var key in base) {
			if(!base.hasOwnProperty(key)) continue;
			if(key == 'title') continue;
			if(key == 'description') continue;

			var param = base[key];
			basehtml += '<div class="cvss2-param col-md-6">';
			basehtml += '<label class="subtitle" data-placeent="top" data-toggle="tooltip" id="'+param.shortTitle+'" title="'+param.description+'">'+param.title+'*</label>';
			basehtml += '<div class="cvss2-options">';
			for(var option in param.scores) {
				basehtml += '<input class="hidden" type="radio" id="'+param.scores[option].shortTitle.replace(':','_')+'" value="'+param.scores[option].shortTitle+'">';
				basehtml += '<label id="lbl'+param.scores[option].shortTitle.replace(':','_')+'" class="btn btn-xs btn-default" data-placement="top" data-toggle="tooltip" title="'+param.scores[option].description+'" for="'+param.scores[option].shortTitle+'">'+param.scores[option].title + ' (' + param.scores[option].shortTitle + ')' +'</label>';
			}
			basehtml += '</div>'
			basehtml += '</div>';
		}
		basehtml += '</div></div><div class="clearfix"></div>';
		$(basehtml).appendTo(hook);
		
		//generate temporal html as hidden
		var temporalhtml = '<div class="cvss2-temporal-form"><label class="title" data-placement="top" data-toggle="tooltip" title="'+temporal.description+'">+ '+temporal.title+'</label>';
		temporalhtml += '<div class="clearfix"></div><div class="cvss2-temporal-inner" style="display:none">';

		for(var key in temporal) {
			if(!temporal.hasOwnProperty(key)) continue;
			if(key == 'title') continue;
			if(key == 'description') continue;

			var param = temporal[key];
			temporalhtml += '<div class="cvss2-param col-md-12">';
			temporalhtml += '<label class="subtitle" data-placeent="top" data-toggle="tooltip" id="'+param.shortTitle+'" title="'+param.description+'">'+param.title+'</label>';
			temporalhtml += '<div class="cvss2-options">';
			for(var option in param.scores) {
				temporalhtml += '<input class="hidden" type="radio" id="'+param.scores[option].shortTitle.replace(':','_')+'" value="'+param.scores[option].shortTitle+'">';
				temporalhtml += '<label id="lbl'+param.scores[option].shortTitle.replace(':','_')+'" class="btn btn-xs btn-default" data-placement="top" data-toggle="tooltip" title="'+param.scores[option].description+'" for="'+param.scores[option].shortTitle+'">'+param.scores[option].title + ' (' + param.scores[option].shortTitle + ')' +'</label>';
			}
			temporalhtml += '</div>'
			temporalhtml += '</div>';
		}
		temporalhtml += '</div></div><div class="clearfix"></div>';
		$(temporalhtml).appendTo(hook);

		//generate environmental as hidden
		var environmentalhtml = '<div class="cvss2-environmental-form"><label class="title" data-placement="top" data-toggle="tooltip" title="'+environmental.description+'">+ '+environmental.title+'</label>';
		environmentalhtml += '<div class="clearfix"></div><div class="cvss2-environmental-inner" style="display:none">';

		for(var key in environmental) {
			if(!environmental.hasOwnProperty(key)) continue;
			if(key == 'title') continue;
			if(key == 'description') continue;

			var param = environmental[key];
			environmentalhtml += '<div class="cvss2-param col-md-12">';
			environmentalhtml += '<label class="subtitle" data-placeent="top" data-toggle="tooltip" id="'+param.shortTitle+'" title="'+param.description+'"> '+param.title+'</label>';
			environmentalhtml += '<div class="cvss2-options">';
			for(var option in param.scores) {
				environmentalhtml += '<input class="hidden" type="radio" id="'+param.scores[option].shortTitle.replace(':','_')+'" value="'+param.scores[option].shortTitle+'">';
				environmentalhtml += '<label id="lbl'+param.scores[option].shortTitle.replace(':','_')+'" class="btn btn-xs btn-default" data-placement="top" data-toggle="tooltip" title="'+param.scores[option].description+'" for="'+param.scores[option].shortTitle+'">'+param.scores[option].title + ' (' + param.scores[option].shortTitle + ')' +'</label>';
			}
			environmentalhtml += '</div>'
			environmentalhtml += '</div>';
		}
		environmentalhtml += '</div></div><div class="clearfix"></div>';
		$(environmentalhtml).appendTo(hook);


		if(loadbuttons) {
			$('<button class="button fusion-button button-default default button-round button-large large" id="update_scores">Update Scores</button> ').appendTo(hook);
			$('<button class="button fusion-button button-round button-flat button-large large" id="reset_scores">Reset Scores</button>').appendTo(hook);
		}		

		//init tooltips
		$('[data-toggle="tooltip"], .enable-tooltip').tooltip({container: 'body', animation: false});

		//init buttons
		$('.cvss2-options label').click(function() {
			$(this).parent().find('label.btn-primary').removeClass('btn-primary').addClass('btn-default');
			$(this).parent().find('input:radio').attr('checked', false);
			$(hook + ' #' + $(this).attr('id').replace('lbl','')).attr('checked',true);
			$(this).removeClass('btn-default').addClass('btn-primary');
		});

		//init defaults
		this.resetHTMLInputs(hook);
		
		//hide temporal & environmental
		$('label.title').click(function() {
			var cls = $(this).parent().attr('class');
			cls = cls.replace('-form','');

			$('.'+cls+'-inner').toggle('slow');
			var first = $(this).html().substr(0, 1);
			if(first == '-')
				first = '+';
			else
				first = '-';
			$(this).html(first + $(this).html().substr(1));
		});

		if(loadbuttons) {
			$('#reset_scores').click(function() {
				CVSS2.resetHTMLInputs(hook);
				CVSS2.generateChartsFromScores({
					baseScore : -1,
					impactScore : 0,
					exploitabilitySubScore : 0,
					temporalScore: -1,
					environmentalScore: -1,
					adjustedImpactScore : 0,
					adjustedTemporal : 0,
					adjustedBaseScore : 0,
					overallScore : -1,
				});
				$(hook + ' .vector_url').html('None');
				$('html, body').animate({ scrollTop: 0 }, 800);
			});
		}

		if(window.location.hash.length) {
			this.loadVectorFromHash();
			this.loadLabelsFromVector();
			CVSS2.addHTMLURL(hook);
		}

		if(loadbuttons) {
			$('#update_scores').click(function() {
				CVSS2.computeCVSS2ScoresFromHTML(hook);
				CVSS2.generateChartsFromScores();
				CVSS2.addHTMLURL(hook);
				$('html, body').animate({ scrollTop: 0 }, 800);
			});
		}
	}

})();
