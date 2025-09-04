# Threat Detection with GuardDuty

![Image](http://learn.nextwork.org/restful_olive_calm_riroriro/uploads/aws-security-guardduty_v1w2x3y4)

---

### Tools and concepts

The services I used were Amazon GuardDuty for threat detection and analysis, AWS CloudFormation for automated infrastructure deployment, Amazon EC2 for hosting the vulnerable web application, Amazon S3 for data storage and the target of data exfiltration, Amazon CloudFront for content delivery, AWS CloudShell for simulating external attacker behavior, and GuardDuty's S3 Malware Protection for file-based threat detection.
Key concepts I learnt include how multi-stage cyberattacks progress from initial web application compromise through credential theft to data exfiltration, demonstrating the attack chain methodology used by sophisticated threat actors. I gained hands-on experience with common web vulnerabilities including SQL injection for authentication bypass and command injection for arbitrary code execution on web servers.

### Project reflection

This project took me almost 2 hours to complete from initial CloudFormation deployment through the final malware protection testing. The most challenging part was simply waiting for AWS to allocate my resources during the CloudFormation. It was most rewarding to see the complete attack chain come together and exfiltrate the data.

I want to become job-ready. This project met my learning goals by providing concrete experience with both offensive and defensive security techniques

---

## Project Setup

To set up for this project, I deployed a CloudFormation template that launches a complete vulnerable web application environment with 27 AWS resources designed to create a realistic attack surface. The three main components are the web application infrastructure, S3 storage containing sensitive data, and GuardDuty threat detection monitoring.

The web app deployed is called the OWASP Juice Shop, a deliberately vulnerable application designed for security training and penetration testing exercises. To practice my GuardDuty skills, I will execute an attack campaign against this application to test the threat detection capabilities of AWS's machine learning-powered security monitoring.

GuardDuty is AWS's intelligent threat detection service that uses machine learning algorithms and threat intelligence to continuously monitor AWS accounts for malicious activity and unauthorized behavior. It analyzes multiple data sources including VPC Flow Logs, DNS logs, CloudTrail event logs, and S3 data events to identify patterns that indicate potential security threats such as compromised instances, cryptocurrency mining, data exfiltration, or reconnaissance activities.
In this project, it will monitor all the attack activities I'll execute against the web application. GuardDuty will establish baseline behavioral patterns for the EC2 instance, S3 bucket access patterns, and network traffic flows during normal operation. When I perform the SQL injection, command injection, credential theft, and data exfiltration attacks, GuardDuty's anomaly detection algorithms will identify these activities as deviations from established norms.

![Image](http://learn.nextwork.org/restful_olive_calm_riroriro/uploads/aws-security-guardduty_n1o2p3q4)

---

## SQL Injection

The first attack I performed on the web app is SQL injection, which means I manipulated the application's database query by inserting malicious SQL code through user input fields that weren't properly validated or sanitized. SQL injection is a security risk because it allows attackers to bypass authentication controls, access unauthorized data, modify database contents, or execute administrative operations on the database server.

My SQL injection attack involved entering the malicious string ' or 1=1;-- into the email field of the login form. The attack works by breaking out of the expected parameter structure - the single quote terminates the email string, or 1=1 injects a condition that always evaluates to true, and the double dash comments out the remainder of the query including the password verification. When the application processes this input, it transforms a legitimate authentication query into one that automatically grants access regardless of actual credentials.
The vulnerability exists because the application uses string concatenation or insecure query construction methods rather than parameterized queries or prepared statements. Instead of treating user input as data, the application interprets the injected SQL syntax as executable code, allowing me to manipulate the query logic and gain unauthorized administrative access to the system.

![Image](http://learn.nextwork.org/restful_olive_calm_riroriro/uploads/aws-security-guardduty_h1i2j3k4)

---

## Command Injection

Next, I used command injection, which is a vulnerability that occurs when an application executes user-supplied input as system commands without proper validation or sanitization, allowing attackers to run arbitrary code on the underlying server. The Juice Shop web app is vulnerable to this because it fails to sanitize the username input field, treating the JavaScript payload as executable code rather than simple text data.
The injected payload exploits the EC2 instance metadata service by forcing the web server to retrieve its own IAM credentials and expose them publicly. The command constructs a shell script that first obtains a session token from the metadata service, then uses that token to retrieve the instance's temporary AWS credentials, and finally saves those credentials to a publicly accessible JSON file within the web application's directory structure.

To run command injection, I pasted a malicious JavaScript payload into the username field of the admin profile page, exploiting the application's failure to sanitize user input before processing it as executable code. The script will force the web server to access the EC2 instance metadata service, retrieve the temporary IAM credentials assigned to the instance, and save those credentials to a publicly accessible JSON file within the web application's directory structure.

![Image](http://learn.nextwork.org/restful_olive_calm_riroriro/uploads/aws-security-guardduty_t3u4v5w6)

---

## Attack Verification

To verify the attack's success, I confirmed that the username field displayed "[object Object]" instead of the injected code, indicating that a JavaScript object had been created and executed rather than simply stored as text. The credentials page showed me the complete AWS IAM credentials in JSON format, including the AccessKeyId, SecretAccessKey, session Token, expiration timestamp, and credential status information.
Then I went to access the credentials.json file follwing the path created in the URL which revealed the stolen temporary AWS credentials extracted from the EC2 metadata service. The JSON structure contained all the necessary components for programmatic AWS access, demonstrating that the command injection had successfully forced the web server to retrieve its own IAM role credentials and expose them through a publicly accessible endpoint within the application's file structure.

![Image](http://learn.nextwork.org/restful_olive_calm_riroriro/uploads/aws-security-guardduty_x7y8z9a0)

---

## Using CloudShell for Advanced Attacks

The attack continues in CloudShell, because this is how attackers would use the stolen credentials to access AWS resources from outside the compromised infrastructure. CloudShell runs in a separate AWS account context with a different account ID than the one hosting the vulnerable web application, which creates the cross-account credential usage pattern that GuardDuty's anomaly detection algorithms are specifically designed to identify as suspicious behavior.


In CloudShell, I used wget to download the credentials.json file from the publicly accessible URL created by the command injection attack, retrieving the stolen AWS credentials that were exposed through the web application's vulnerability. Next, I ran a command using cat and jq to display and format the JSON credentials file in a readable structure, allowing me to verify the contents and prepare for configuring the AWS CLI profile.

I then set up a profile, called "stolen," to configure the AWS CLI with the compromised credentials extracted from the web application, enabling me to authenticate as the EC2 instance and access AWS resources using its permissions. I had to create a new profile because CloudShell's default profile uses my legitimate IAM user credentials, and mixing those with the stolen temporary credentials would prevent the simulation from generating the cross-account anomaly detection that GuardDuty needs to identify this as suspicious activity.

![Image](http://learn.nextwork.org/restful_olive_calm_riroriro/uploads/aws-security-guardduty_j9k0l1m2)

---

## GuardDuty's Findings

After performing the attack, GuardDuty reported a finding within approximately 5 minutes of the credential exfiltration activity, demonstrating rapid threat detection capabilities. Findings are security alerts generated by GuardDuty's machine learning algorithms when they identify activities that deviate from established baseline behavior patterns or match known threat indicators.

GuardDuty's finding was called "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS" which means that credentials assigned to an EC2 instance were detected being used from a different AWS account to access resources in an unauthorized manner, indicating potential credential theft and data exfiltration. Anomaly detection was used because GuardDuty's machine learning algorithms established baseline patterns for how the EC2 instance's IAM role credentials should be used within the original account context, and the cross-account usage from CloudShell (account 370314719932) represented a significant deviation from normal behavior.

GuardDuty's detailed finding reported that credentials created exclusively for EC2 instance role "NextWork-GuardDuty-project-Tega-TheRole-VTrSQqR9Khv1" were used from remote AWS account 370314719932 to perform unauthorized S3 GetObject operations against the "nextwork-guardduty-project-tega-thesecurebucket-egeapiuk4nyr" bucket. The finding provided comprehensive forensic details including the specific Access Key ID (ASIA2S2Y4HBBH4FPYW2C), the source IP address (52.90.248.85) originating from Amazon's Ashburn data center, and the exact timestamp of the suspicious API call at 20:50:18.

![Image](http://learn.nextwork.org/restful_olive_calm_riroriro/uploads/aws-security-guardduty_v1w2x3y4)

---

## Extra: Malware Protection

For my project extension, I enabled S3 Malware Protection within GuardDuty to scan objects uploaded to the S3 bucket for malicious files and known malware signatures. Malware is software specifically designed to damage, disrupt, or gain unauthorized access to computer systems, and it can steal sensitive data, corrupt files, or provide attackers with persistent access to compromised infrastructure.

To test Malware Protection, I uploaded an EICAR test file, which is a standard text file containing a specific string that antivirus and malware detection systems are programmed to recognize as a test signature for validation purposes. The uploaded file won't actually cause damage because it contains only harmless text designed specifically for testing security systems - it's not real malware but rather a universally recognized test pattern that triggers detection algorithms without any malicious functionality.


Once I uploaded the file, GuardDuty instantly triggered a HIGH severity finding classified as "Object:S3/MaliciousFile" pertaining to the EICAR test file being uploaded to the S3 bucket. This verified that GuardDuty's S3 Malware Protection is properly configured and functioning as designed, successfully scanning uploaded objects and identifying files that match known malware signatures or suspicious patterns.

![Image](http://learn.nextwork.org/restful_olive_calm_riroriro/uploads/aws-security-guardduty_sm42x3y4)

---
