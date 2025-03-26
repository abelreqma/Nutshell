--Trigger is at the end of the script, above the queries
DROP TABLE DeviceService;
DROP TABLE VulnService;
DROP TABLE Device;
DROP TABLE Service;
DROP TABLE Account;
DROP TABLE Risk;
DROP TABLE Vulnerability;
DROP TABLE Windows;
DROP TABLE Linux;
DROP TABLE MacOS;
DROP TABLE OperatingSystem;
DROP TABLE ServiceChangeHistory;
DROP SEQUENCE dsid_seq;
DROP SEQUENCE vulnid_seq;
DROP SEQUENCE device_id_seq;
DROP SEQUENCE service_id_seq;
DROP SEQUENCE user_id_seq;
DROP SEQUENCE risk_id_seq;
DROP SEQUENCE exploit_id_seq;
DROP SEQUENCE os_id_seq;
DROP SEQUENCE history_id_seq;
DROP PROCEDURE add_user;
DROP PROCEDURE linux_os;
DROP PROCEDURE add_mac_os;
DROP PROCEDURE windows_os;
DROP PROCEDURE add_device;
DROP PROCEDURE tcp_service;
DROP PROCEDURE udp_service;
DROP PROCEDURE add_risk;
DROP PROCEDURE add_exploit;
DROP PROCEDURE link_devser;
DROP PROCEDURE add_vulnservice;
DROP VIEW Vulnerable_Devices;

--TABLES
CREATE TABLE Account (
UserID INTEGER PRIMARY KEY,
FirstName VARCHAR(64) NOT NULL,
LastName VARCHAR(64) NOT NULL, 
EmailAddress VARCHAR(100) UNIQUE NOT NULL,
PhoneNumber VARCHAR(12) UNIQUE NOT NULL,
CONSTRAINT Account_em CHECK(EmailAddress LIKE '%@%.%'));

CREATE TABLE OperatingSystem(
OS_ID INTEGER PRIMARY KEY,
OS_Name VARCHAR(7),
OS_RDate DATE NOT NULL);

CREATE TABLE Windows(
OS_ID INTEGER PRIMARY KEY,
OS_Version VARCHAR(40) UNIQUE,
FOREIGN KEY(OS_ID) REFERENCES OperatingSystem(OS_ID));

CREATE TABLE Linux(
OS_ID INTEGER PRIMARY KEY,
Distribution VARCHAR(32) NOT NULL,
OS_Version VARCHAR(40) UNIQUE,
FOREIGN KEY(OS_ID) REFERENCES OperatingSystem(OS_ID));

CREATE TABLE MacOS(
OS_ID INTEGER PRIMARY KEY,
OS_Version VARCHAR(40) UNIQUE,
FOREIGN KEY(OS_ID) REFERENCES OperatingSystem(OS_ID));

CREATE TABLE Device(
DeviceID INTEGER PRIMARY KEY,
UserID INTEGER NOT NULL,
OS_ID INTEGER NOT NULL, 
Purpose VARCHAR(255),
DeviceType VARCHAR(20) NOT NULL,
MACAddress VARCHAR(17) UNIQUE,
FOREIGN KEY(UserID) REFERENCES Account(UserID),
FOREIGN KEY(OS_ID) REFERENCES OperatingSystem(OS_ID));

CREATE TABLE Vulnerability(
ExploitID INTEGER PRIMARY KEY,
OS_ID INTEGER NULL,
ExploitName VARCHAR(100) NOT NULL,
Platform VARCHAR(10) NOT NULL,
ExploitType VARCHAR(7) NOT NULL, 
DateSubmit DATE NOT NULL, 
Description VARCHAR(255),
CONSTRAINT Vuln_et CHECK(ExploitType IN ('local', 'remote', 'webapps', 'DoS')),
FOREIGN KEY(OS_ID) REFERENCES OperatingSystem(OS_ID));

CREATE TABLE Risk(
RiskID INTEGER PRIMARY KEY, 
ExploitID INTEGER NOT NULL,
MitigationPrevention VARCHAR(1024), 
CVSSScore DECIMAL(3,1),
Severity VARCHAR(6),
Impact VARCHAR(1024) NOT NULL, 
CONSTRAINT Risk_csc CHECK(CVSSScore BETWEEN 0 AND 10),
CONSTRAINT Risk_sev CHECK(Severity IN ('low', 'medium', 'high')),
FOREIGN KEY(ExploitID) REFERENCES Vulnerability(ExploitID));

CREATE TABLE Service(
ServiceID INTEGER PRIMARY KEY,
ServiceName VARCHAR(30) NOT NULL,
ServicePort VARCHAR(5) NOT NULL,
ServiceVersion VARCHAR(64) NOT NULL,
TCPOrUDP CHAR(3),
CONSTRAINT Service_TU CHECK(TCPOrUDP IN ('TCP', 'UDP')));

CREATE TABLE DeviceService(
DSID INTEGER PRIMARY KEY,
DeviceID INTEGER NOT NULL,
ServiceID INTEGER NOT NULL,
FOREIGN KEY(DeviceID) REFERENCES Device(DeviceID),
FOREIGN KEY(ServiceID) REFERENCES Service(ServiceID));

CREATE TABLE VulnService(
VulnID INTEGER PRIMARY KEY,
ServiceID INTEGER,
ExploitID INTEGER,
DeviceID INTEGER,
FOREIGN KEY(ServiceID) REFERENCES Service(ServiceID),
FOREIGN KEY(ExploitID) REFERENCES Vulnerability(ExploitID),
FOREIGN KEY(DeviceID) REFERENCES Device(DeviceID));

CREATE TABLE ServiceChangeHistory(
HistID INTEGER PRIMARY KEY,
DeviceID INTEGER NOT NULL,
OldServiceID INTEGER NOT NULL,
NewServiceID INTEGER,
OldService VARCHAR(100) NOT NULL,
NewService VARCHAR(100),
ServPort VARCHAR(5) NOT NULL,
ChangeDate DATE NOT NULL);


--SEQUENCES
CREATE SEQUENCE user_id_seq START WITH 1;		--Account entity PK sequence
CREATE SEQUENCE exploit_id_seq START WITH 1;	--Vulnerability entity PK sequence
CREATE SEQUENCE risk_id_seq START WITH 1;		--Risk entity PK sequence
CREATE SEQUENCE os_id_seq START WITH 1;			--OperatingSystem (and subtype) entities PK sequence
CREATE SEQUENCE device_id_seq START WITH 1;		--Device entity PK sequence
CREATE SEQUENCE service_id_seq START WITH 1;	--Service entity PK sequence
CREATE SEQUENCE dsid_seq START WITH 1;			--DeviceService junction entity PK sequence
CREATE SEQUENCE vulnid_seq START WITH 1;		--VulnService junction entity PK sequence
CREATE SEQUENCE history_id_seq START WITH 1;	--ServiceChangeHistory entity PK squence


--INDEXES
CREATE INDEX DeviceUserIdx	--Device FK of Account index
ON Device(UserID);

CREATE INDEX DeviceOSIdx	--Device FK of OperatingSystem index
ON Device(OS_ID);

CREATE INDEX VulnOSIdx		--Vulnerability FK of OperatingSystem index
ON Vulnerability(OS_ID);

CREATE UNIQUE INDEX RiskExpIdx -- Risk FK of Vulnerability index 
ON Risk(ExploitID);

CREATE INDEX DevSerDIDIdx	--DeviceService FK of Device index
ON DeviceService(DeviceID);

CREATE INDEX DevServSIDIdx	--DeviceService FK of Service index
ON DeviceService(ServiceID);

CREATE INDEX VulnServSIDIdx	--VulnService FK of Service index
ON VulnService(ServiceID);

CREATE INDEX VulnServDIDIdx	--VulnService FK of Device index
ON VulnService(DeviceID);

CREATE INDEX VulnServEIDIdx --VulnService FK of Vulnerability index
ON VulnService(ExploitID);

CREATE UNIQUE INDEX AcctEmailIdx --Email index on Account
ON Account(EmailAddress);

CREATE INDEX ServNameIdx		--Service name index on Service
ON Service(ServiceName);

CREATE UNIQUE INDEX DevMACAddrIdx	--MAC address index on Device
ON Device(MACAddress);

CREATE INDEX VulnExpNameIdx		--Exploit name index on Vulnerability
ON Vulnerability(ExploitName);


--STORED PROCEDURES
CREATE OR ALTER PROCEDURE add_user --adds row to Account entity
	@first_name_arg VARCHAR(64),
	@last_name_arg VARCHAR(64),
	@email_arg VARCHAR(100),
	@phone_num_arg VARCHAR(12)
AS
BEGIN
	INSERT INTO Account(UserID, FirstName, LastName, EmailAddress, PhoneNumber)
	VALUES(NEXT VALUE FOR user_id_seq, @first_name_arg, @last_name_arg, @email_arg, @phone_num_arg);
END;


CREATE OR ALTER PROCEDURE linux_os --adds row to the OperatingSystem supertype and Linux subtype
	@release_date_arg DATE,
	@distro_arg VARCHAR(32),
	@os_ver_arg VARCHAR(20)
AS
BEGIN
	DECLARE @os_id INTEGER;
	SET @os_id = NEXT VALUE FOR os_id_seq

	INSERT INTO OperatingSystem(OS_ID, OS_Name, OS_RDate)
	VALUES(@os_id, 'Linux', @release_date_arg);

	INSERT INTO Linux(OS_ID, Distribution, OS_Version)
	VALUES(@os_id, @distro_arg, @os_ver_arg);
END;


CREATE OR ALTER PROCEDURE add_mac_os --adds row to the OperatingSystem supertype and MacOS subtype
	@release_date_arg DATE,
	@os_ver_arg VARCHAR(20)
AS
BEGIN
	DECLARE @os_id INTEGER;
	SET @os_id = NEXT VALUE FOR os_id_seq

	INSERT INTO OperatingSystem(OS_ID, OS_Name, OS_RDate)
	VALUES(@os_id, 'MacOS', @release_date_arg);

	INSERT INTO MacOS(OS_ID, OS_Version)
	VALUES(@os_id, @os_ver_arg);
END;


CREATE OR ALTER PROCEDURE windows_os --adds row to the OperatingSystem supertype and Windows subtype
	@release_date_arg DATE,
	@os_ver_arg VARCHAR(20)
AS
BEGIN
	DECLARE @os_id INTEGER;
	SET @os_id = NEXT VALUE FOR os_id_seq

	INSERT INTO OperatingSystem(OS_ID, OS_Name, OS_RDate)
	VALUES(@os_id, 'Windows', @release_date_arg);

	INSERT INTO Windows(OS_ID, OS_Version)
	VALUES(@os_id, @os_ver_arg);
END;


CREATE OR ALTER PROCEDURE add_device --adds row to the Device entity
	@demailaddr VARCHAR(100),
	@dos_id INTEGER,
	@devpurpose VARCHAR(255),
	@dev_type VARCHAR(20),
	@devaddr VARCHAR(17)

AS
BEGIN
	DECLARE @devuser_id INTEGER;
	SET @devuser_id = (SELECT UserID FROM Account WHERE EmailAddress = @demailaddr);

	INSERT INTO Device(DeviceID, UserID, OS_ID, Purpose, DeviceType, MACAddress)
	VALUES(NEXT VALUE FOR device_id_seq, @devuser_id, @dos_id, @devpurpose, @dev_type, @devaddr);
END;


CREATE OR ALTER PROCEDURE tcp_service --adds row to Service entity, specifically TCP service
	@serv_name VARCHAR(30), 
	@serv_port VARCHAR(5),
	@serv_ver VARCHAR(64)
AS
BEGIN
	INSERT INTO Service(ServiceID, ServiceName, ServicePort, ServiceVersion, TCPOrUDP)
	VALUES(NEXT VALUE FOR service_id_seq, @serv_name, @serv_port, @serv_ver, 'TCP');
END;

CREATE OR ALTER PROCEDURE udp_service --adds row to Service entity, specifically UDP service
	@serv_name VARCHAR(30), 
	@serv_port VARCHAR(5),
	@serv_ver VARCHAR(64)
AS
BEGIN
	INSERT INTO Service(ServiceID, ServiceName, ServicePort, ServiceVersion, TCPOrUDP)
	VALUES(NEXT VALUE FOR service_id_seq, @serv_name, @serv_port, @serv_ver, 'UDP');
END;


CREATE OR ALTER PROCEDURE add_risk --adds row to Risk entity
	@exp_name VARCHAR(100),
	@mprev VARCHAR(1024),
	@cvss DECIMAL(3,1),
	@sev VARCHAR(6),
	@impact VARCHAR(1024)
AS
BEGIN
	DECLARE @exp_id INTEGER;
	SET @exp_id = (SELECT ExploitID FROM Vulnerability WHERE ExploitName = @exp_name)

	INSERT INTO Risk(RiskID, ExploitID, MitigationPrevention, CVSSScore, Severity, Impact)
	VALUES(NEXT VALUE FOR risk_id_seq, @exp_id, @mprev, @cvss, @sev, @impact);
END;


CREATE OR ALTER PROCEDURE add_exploit --adds row to Vulnerability entity
	@exp_name VARCHAR(100),
	@platform VARCHAR(10),
	@exp_type VARCHAR(7),
	@submit_date DATE,
	@descr VARCHAR(255)
AS
BEGIN
	INSERT INTO Vulnerability(ExploitID, OS_ID , ExploitName, Platform, ExploitType, DateSubmit, Description)
	VALUES(NEXT VALUE FOR exploit_id_seq, NULL, @exp_name, @platform, @exp_type, @submit_date, @descr);
END;


CREATE OR ALTER PROCEDURE link_devser --adds row to DeviceService junction entity
	@macaddr VARCHAR(17),
	@servname VARCHAR(30),
	@servport VARCHAR(5),
	@serv_ver VARCHAR(64)
AS
BEGIN
	DECLARE @dev_id INTEGER;
	SET @dev_id = (SELECT DeviceID FROM Device WHERE MACAddress = @macaddr)

	DECLARE @ser_id INTEGER;
	SET @ser_id = (SELECT ServiceID FROM Service 
				   WHERE ServiceName = @servname AND
				   ServicePort = @servport AND
				   ServiceVersion = @serv_ver)

	INSERT INTO DeviceService(DSID, DeviceID, ServiceID)
	VALUES(NEXT VALUE FOR dsid_seq, @dev_id, @ser_id);
END;


CREATE OR ALTER PROCEDURE add_vulnservice --adds row to VulnService junction entity
	@servname VARCHAR(30),
	@servport VARCHAR(5),
	@serv_ver VARCHAR(64),
	@exp_name VARCHAR(100),
	@macaddr VARCHAR(17)
AS
BEGIN
	DECLARE @dev_id INTEGER;
	SET @dev_id = (SELECT DeviceID FROM Device WHERE MACAddress = @macaddr)

	DECLARE @exp_id INTEGER;
	SET @exp_id = (SELECT ExploitID FROM Vulnerability WHERE ExploitName = @exp_name)

	DECLARE @ser_id INTEGER;
	SET @ser_id = (SELECT ServiceID FROM Service 
				   WHERE ServiceName = @servname AND
				   ServicePort = @servport AND
				   ServiceVersion = @serv_ver)

	INSERT INTO VulnService(VulnID, ServiceID, ExploitID, DeviceID)
	VALUES(NEXT VALUE FOR vulnid_seq, @ser_id, @exp_id, @dev_id)
END;


--INSERTS
BEGIN TRANSACTION add_user;
EXECUTE add_user 'Abel', 'Maldonado', 'abel@mail.com', '415-456-7891';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_user;
EXECUTE add_user 'test', 'user', 'test@test.com', '000-000-0000';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_user;
EXECUTE add_user 'Mark', 'Grayson', 'invincible@mail.com', '312-123-4545';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_user;
EXECUTE add_user 'Steve', 'Jobs', 'sjobs@icloud.com', '650-456-4824';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_user;
EXECUTE add_user 'Bill', 'Gates', 'bgates@outlook.com', '206-987-6543';
COMMIT TRANSACTION;


BEGIN TRANSACTION linux_os;
EXECUTE linux_os '10-OCT-2024', 'Ubuntu', '24.10';
COMMIT TRANSACTION;

BEGIN TRANSACTION linux_os;
EXECUTE linux_os '16-DEC-2024', 'Kali', '2024.4';
COMMIT TRANSACTION;

BEGIN TRANSACTION linux_os;
EXECUTE linux_os '29-MAR-2024', 'Arch', '2024.03.29';
COMMIT TRANSACTION;

BEGIN TRANSACTION linux_os;
EXECUTE linux_os '18-AUG-2020', 'Ubuntu', '16.04.7';
COMMIT TRANSACTION;

BEGIN TRANSACTION linux_os;
EXECUTE linux_os '17-MAY-2022', 'Red Hat', 'RHEL 9.0';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_mac_os;
EXECUTE add_mac_os '26-SEP-2023', 'MacOS 14 Sonoma';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_mac_os;
EXECUTE add_mac_os '16-OCT-2014', 'OS X 10.10 Yosemite';
COMMIT TRANSACTION;

BEGIN TRANSACTION windows_os;
EXECUTE windows_os '30-JAN-2007', 'Windows Vista NT 6.0';
COMMIT TRANSACTION;

BEGIN TRANSACTION windows_os;
EXECUTE windows_os '4-OCT-2021', 'Windows 11 21H2';
COMMIT TRANSACTION;

BEGIN TRANSACTION windows_os;
EXECUTE windows_os '29-OCT-2002', 'Windows XP NT 5.1';
COMMIT TRANSACTION;

BEGIN TRANSACTION windows_os;
EXECUTE windows_os '1-NOV-2024', 'Windows Server 24H2';
COMMIT TRANSACTION;


BEGIN TRANSACTION add_device;
EXECUTE add_device 'abel@mail.com', 1, 'multipurpose server', 'server', 'A1-B2-C3-D4-E5-F6';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_device;
EXECUTE add_device 'invincible@mail.com', 5, 'ssh server', 'server', 'F1-E2-D3-C4-B5-A6';
COMMIT TRANSACTION;


BEGIN TRANSACTION add_device;
EXECUTE add_device 'sjobs@icloud.com', 7, 'telnet server', 'laptop', 'D1-C2-E3-A4-B5-C6';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_device;
EXECUTE add_device 'bgates@outlook.com', 8, 'sql server', 'server', 'C3-C2-A3-B2-E1-A4';
COMMIT TRANSACTION;


BEGIN TRANSACTION tcp_service;
EXECUTE tcp_service  'telnet', '23', '2.5';
COMMIT TRANSACTION;

BEGIN TRANSACTION tcp_service;
EXECUTE tcp_service 'OpenSSH', '22', '6.6.1p1';
COMMIT TRANSACTION;

BEGIN TRANSACTION tcp_service;
EXECUTE tcp_service 'OpenSSH', '22', '6.4';
COMMIT TRANSACTION;

BEGIN TRANSACTION tcp_service;
EXECUTE tcp_service 'Apache httpd', '80', '2.4.7';
COMMIT TRANSACTION;

BEGIN TRANSACTION tcp_service;
EXECUTE tcp_service 'vsftpd', '21', '2.3.4';
COMMIT TRANSACTION;

BEGIN TRANSACTION tcp_service;
EXECUTE tcp_service 'MariaDB', '3306', '11.4.3';
COMMIT TRANSACTION;

BEGIN TRANSACTION udp_service;
EXECUTE udp_service 'FreeRadius', '1812', '0.9.2';
COMMIT TRANSACTION;

BEGIN TRANSACTION udp_service;
EXECUTE udp_service 'Net-SNMP', '161', '5.3.1';
COMMIT TRANSACTION;

BEGIN TRANSACTION tcp_service;
EXECUTE tcp_service 'OpenSMTPD', '25', '6.6.2';
COMMIT TRANSACTION;

BEGIN TRANSACTION tcp_service;
EXECUTE tcp_service 'MariaDB', '3306', '10.2';
COMMIT TRANSACTION;

BEGIN TRANSACTION tcp_service;
EXECUTE tcp_service 'OpenSSH', '22', '9.9p2';
COMMIT TRANSACTION;

BEGIN TRANSACTION tcp_service;
EXECUTE tcp_service 'tnftp', '21', '20230507';
COMMIT TRANSACTION;



BEGIN TRANSACTION add_exploit;
EXECUTE add_exploit 'Tag Field Heap Corruption', 'Linux', 'DoS', '20-NOV-2003', 'FreeRADIUS 0.9.2 allows remote attackers to cause a DoS via a short RADIUS string attribute with a tag, 
																  which causes memcpy to be called with a -1 length argument.';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_exploit;
EXECUTE add_exploit 'Backdoor Command Execution', 'UNIX', 'Remote', '12-APR-2021', 'vsftpd 2.3.4 downloaded between 20110630 and 20110703 
																					contains a backdoor which opens a shell on port 6200/tcp.';
COMMIT TRANSACTION;


BEGIN TRANSACTION add_exploit;
EXECUTE add_exploit 'Username Enumeration', 'Linux', 'Remote', '21-AUG-2018', 'OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout 
																			   for an invalid authenticating user until after the packet containing the request has been fully parsed.';
COMMIT TRANSACTION;


BEGIN TRANSACTION add_exploit;
EXECUTE add_exploit 'HMAC Validation Error Remote Authentication Bypass', 'Multiple', 'Remote', '12-JUN-2008', 'SNMPv3 HMAC verification in Net-SNMP 5.2.x before 5.2.4.1, 5.3.x 
																												before 5.3.2.1, and 5.4.x before 5.4.1.1 relies on the client to specify
																												the HMAC length, making it easier for attackers to bypass SNMP authentication';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_exploit;
EXECUTE add_exploit 'OOB Read Local Privilege Escalation (Metasploit)', 'Linux', 'Local', '09-MAR-2020', 'OpenSMTPD before 6.6.4 allows RCE because of an out-of-bounds read in mta_io
																										  in mta_session.c for multi-line replies. It is possible to attack the server because
																										  the server code launches the client code during bounce handling.';
COMMIT TRANSACTION;


BEGIN TRANSACTION add_exploit;
EXECUTE add_exploit 'wsrep_provider OS command execution', 'Linux', 'Local', '14-APR-2021', 'RCE is possible in MariaDB 10.2 before 10.2.37, 10.3 before 10.3.28, 10.4 before 10.4.18, 
																							 and 10.5 before 10.5.9. An untrusted search path to eval injection, in which a database SUPER 
																							 user can execute OS commands after modifying wsrep_provider and wsrep_notify_cmd.';
COMMIT TRANSACTION; 


BEGIN TRANSACTION add_exploit;
EXECUTE add_exploit 'ICMPv6 Router Advertisement RCE', 'Windows', 'Remote', '09-FEB-2010', 'The TCP/IP implementation in Microsoft Windows Vista Gold, SP1, and SP2 and Server 2008 Gold 
																							and SP2, when IPv6 is enabled, does not properly perform bounds checking on ICMPv6 Router 
																							Advertisement packets, allowing attackers to execute arbitrary code via crafted packets.';
COMMIT TRANSACTION;

UPDATE Vulnerability
SET OS_ID = (SELECT w.OS_ID FROM Windows w WHERE w.OS_Version = 'Windows Vista NT 6.0')
WHERE Vulnerability.ExploitName = 'ICMPv6 Router Advertisement RCE';


BEGIN TRANSACTION add_exploit;
EXECUTE add_exploit 'Zero-Length Tunnel-Password DoS', 'Multiple', 'DoS', '11-SEP-2009', 'The rad_decode function in FreeRADIUS before 1.1.8 allows remote attackers to cause a DoS via 
																						  zero-length Tunnel-Password attributes.';
COMMIT TRANSACTION;


BEGIN TRANSACTION add_exploit;
EXECUTE add_exploit 'Backdoor Command Execution (Metasploit)', 'UNIX', 'Remote', '05-JUL-2011', 'vsftpd 2.3.4 downloaded between 20110630 and 20110703 
																					contains a backdoor which opens a shell on port 6200/tcp.';
COMMIT TRANSACTION;


BEGIN TRANSACTION link_devser;
EXECUTE link_devser 'A1-B2-C3-D4-E5-F6', 'Apache httpd', '80', '2.4.7';
COMMIT TRANSACTION;

BEGIN TRANSACTION link_devser;
EXECUTE link_devser 'A1-B2-C3-D4-E5-F6', 'FreeRadius', '1812', '0.9.2';
COMMIT TRANSACTION;

BEGIN TRANSACTION link_devser;
EXECUTE link_devser 'A1-B2-C3-D4-E5-F6', 'OpenSSH', '22', '6.6.1p1';
COMMIT TRANSACTION;

BEGIN TRANSACTION link_devser;
EXECUTE link_devser 'F1-E2-D3-C4-B5-A6', 'OpenSSH', '22', '6.4';
COMMIT TRANSACTION;

BEGIN TRANSACTION link_devser;
EXECUTE link_devser 'F1-E2-D3-C4-B5-A6', 'vsftpd', '21', '2.3.4';
COMMIT TRANSACTION;

BEGIN TRANSACTION link_devser;
EXECUTE link_devser 'D1-C2-E3-A4-B5-C6', 'telnet', '23', '2.5';
COMMIT TRANSACTION;

BEGIN TRANSACTION link_devser;
EXECUTE link_devser 'C3-C2-A3-B2-E1-A4', 'MariaDB', '3306', '10.2';
COMMIT TRANSACTION;

BEGIN TRANSACTION link_devser;
EXECUTE link_devser 'A1-B2-C3-D4-E5-F6', 'MariaDB', '3306', '11.4.3';
COMMIT TRANSACTION;

BEGIN TRANSACTION link_devser;
EXECUTE link_devser 'A1-B2-C3-D4-E5-F6', 'Net-SNMP', '161', '5.3.1';
COMMIT TRANSACTION;

BEGIN TRANSACTION link_devser;
EXECUTE link_devser 'F1-E2-D3-C4-B5-A6', 'OpenSMTPD', '25', '6.6.2';
COMMIT TRANSACTION;



BEGIN TRANSACTION add_vulnservice;
EXECUTE add_vulnservice 'vsftpd', '21', '2.3.4', 'Backdoor Command Execution', 'F1-E2-D3-C4-B5-A6';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_vulnservice;
EXECUTE add_vulnservice 'vsftpd', '21', '2.3.4', 'Backdoor Command Execution (Metasploit)', 'F1-E2-D3-C4-B5-A6';	
COMMIT TRANSACTION;

BEGIN TRANSACTION add_vulnservice;
EXECUTE add_vulnservice 'OpenSSH', '22', '6.4', 'Username Enumeration', 'F1-E2-D3-C4-B5-A6'; 
COMMIT TRANSACTION;

BEGIN TRANSACTION add_vulnservice;
EXECUTE add_vulnservice 'OpenSSH', '22', '6.6.1p1', 'Username Enumeration', 'A1-B2-C3-D4-E5-F6'; 
COMMIT TRANSACTION;

BEGIN TRANSACTION add_vulnservice;
EXECUTE add_vulnservice 'FreeRadius', '1812', '0.9.2', 'Tag Field Heap Corruption', 'A1-B2-C3-D4-E5-F6'; 
COMMIT TRANSACTION;

BEGIN TRANSACTION add_vulnservice;
EXECUTE add_vulnservice 'FreeRadius', '1812', '0.9.2', 'Zero-Length Tunnel-Password DoS', 'A1-B2-C3-D4-E5-F6'; 
COMMIT TRANSACTION;

BEGIN TRANSACTION add_vulnservice;
EXECUTE add_vulnservice 'Net-SNMP', '161', '5.3.1', 'HMAC Validation Error Remote Authentication Bypass', 'A1-B2-C3-D4-E5-F6'; 
COMMIT TRANSACTION;

BEGIN TRANSACTION add_vulnservice;
EXECUTE add_vulnservice 'OpenSMTPD', '25', '6.6.2', 'OOB Read Local Privilege Escalation (Metasploit)', 'F1-E2-D3-C4-B5-A6';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_vulnservice;
EXECUTE add_vulnservice 'MariaDB', '3306', '10.2', 'wsrep_provider OS command execution' , 'C3-C2-A3-B2-E1-A4';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_vulnservice;
EXECUTE add_vulnservice 'NULL', 'NULL', 'NULL', 'ICMPv6 Router Advertisement RCE', 'C3-C2-A3-B2-E1-A4'; 
COMMIT TRANSACTION;


BEGIN TRANSACTION add_risk;
EXECUTE add_risk 'Tag Field Heap Corruption', 'Update FreeRADIUS to a more recent version, configure firewall rules to only allow trusted clients to communicate with the freeRADIUS server, 
											   enable logging of RADIUS requests', 
											   '5.0', 'Medium', 
											   'A remote attacker can trigger a DoS and users may be unable to log in to the network.';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_risk;
EXECUTE add_risk 'Backdoor Command Execution', 'Upgrade vsftpd to a patched version, implement firewall rules to port 6300, or disable services temporarily until resolved', 
											   '9.8', 'High', 
											   'If exploited, it enables RCE, privilege escalation, system compromise, data integrity risk, and potential DoS and compliance breach.';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_risk;
EXECUTE add_risk 'Username Enumeration', 'Upgrade OpenSSH to a patched version, disable public-facing SSH if it is not needed, enable rate limiting, disable SSH authentication methods 
										  suscpetible to enumeration, only use key-based authentication, restrict SSH access to known users', 
										  '5.3', 'Medium', 
										  'If exploited, it increases the risk of brute-force attacks, potential information disclosure from username enumeration, and potential compliance 
										   and security policy violations';
COMMIT TRANSACTION;

BEGIN TRANSACTION add_risk;
EXECUTE add_risk 'HMAC Validation Error Remote Authentication Bypass', 'Upgrade Net-SNMP to a more recent, patched version, enforce proper HMAC length validation, restrict SNMP access
																		to trusted sources, use stronger authentication and encryption, monitor and log SNMP access and disable unnecessary
																		SNMP services', 
																	   '10', 'High',
																	   'If exploited, attackers can send SNMP reqquests to network devices with manipulated HMAC length, essentially bypassing
																	   any authentication; potential information disclosure by accessing a device; DoS attacks, potential compliance and security
																	   violations';
COMMIT TRANSACTION;


BEGIN TRANSACTION add_risk;
EXECUTE add_risk 'OOB Read Local Privilege Escalation (Metasploit)', 'Upgrade OpenSMTPD to a more recent, patched version, restrict network access to OpenSMTPD, enforce strong authentication
																	 for mail relay policies to prevent abuse, monitor logs for suspicious activity, use a more secure MTA', 
																	 '9.8', 'High',
																	 'If exploited, an attacker could gain RCE by sending a maliciously crafted SMTP request, data exfiltration and sensitive
																	 information disclosure, a potential DoS, and potential compliance and security violations';
COMMIT TRANSACTION;


BEGIN TRANSACTION add_risk;
EXECUTE add_risk 'wsrep_provider OS command execution', 'Upgrade MariaDB or MySQl to a more recent, patched version, review and limit SUPER user access, restrict the ability to modify the
														wsrep_provider and wsrep_notify_cmd parameters to only trusted administrators, use secure file system permissions, use a firewall to
														restrict external access to the database servers, monitor logs for suspicious activity, and disabled unused features', 
														'7.2', 'High',
														'If exploited, an attacker can gain RCE on the database server by exploiting the eval injection, the entire system can be compromised if
														the attacker gains access to a SUPER user account, definite data exfiltration and information disclosure, potential DoS and compliace/security
														violations';
COMMIT TRANSACTION;


BEGIN TRANSACTION add_risk;
EXECUTE add_risk 'ICMPv6 Router Advertisement RCE', 'Apply security updates and patches, upgrade to a newer Windows OS, disable IPv6 if not needed, use firewalls to block ICMPv6 traffic, enable
													DEP and ASLR to prevent RCE, restrict administrative privileges, monitor and audit network traffic, segment networks to limit the spread of 
													an attack', 
													'10.0', 'High',
													'If exploited, an attacker can gain RCE by running malicious code on the target; the attacker could compromise the entire system and install malware
													or backdoors for persistent access; potential information disclosure, DoS, and compliance and security violations';
COMMIT TRANSACTION;


BEGIN TRANSACTION add_risk;
EXECUTE add_risk 'Zero-Length Tunnel-Password DoS', 'Update FreeRADIUS to a more recent version, implement input validation on the attributed being sent to the FreeRADIUS server, limit which users
													can send requests to the FreeRADIUS server using ACLs, use firewalls to block malicious or unauthorized traffic, disable unnecessary RADIUS
													features, configure fail-safe mechanisms on the server to prevent a crash or reduce the impact of the exploitation, regularly monitor the RADIUS logs,
													and implement rate-limiting',
													'5.0', 'Medium',
													'If exploited, an attacker will trigger a DoS, legitimate users will be unable to authenticate to the network, significant loss of availability,
													reputation damage, potential compliance and security violations, and potential financial loss';																	
COMMIT TRANSACTION;


BEGIN TRANSACTION add_risk;
EXECUTE add_risk 'Backdoor Command Execution (Metasploit)', 'Upgrade vsftpd to a patched version, implement firewall rules to port 6300, or disable services temporarily until resolved', 
															'9.8', 'High',
															'If exploited, it enables RCE, privilege escalation, system compromise, data integrity risk, and potential DoS and compliance breach.';
COMMIT TRANSACTION;


--TRIGGERS
CREATE OR ALTER TRIGGER upsrv_change_trg
ON DeviceService
AFTER UPDATE
AS
BEGIN
	DECLARE @device INTEGER = (SELECT DeviceID FROM INSERTED)
	DECLARE @oldserv_id INTEGER = (SELECT ServiceID FROM DELETED)
	DECLARE @newserv_id INTEGER = (SELECT ServiceID FROM INSERTED)
	DECLARE @portcheck1 VARCHAR(5) = (SELECT ServicePort FROM Service WHERE ServiceID = @oldserv_id)
	DECLARE @portcheck2 VARCHAR(5) = (SELECT ServicePort FROM Service WHERE ServiceID = @newserv_id)

	IF @oldserv_id <> @newserv_id
	BEGIN
		IF @portcheck1 = @portcheck2
		BEGIN
			INSERT INTO ServiceChangeHistory(HistID, DeviceID, OldServiceID, NewServiceID, 
											OldService, NewService, ServPort, ChangeDate)
			VALUES(NEXT VALUE FOR history_id_seq, @device, @oldserv_id, @newserv_id, 
			(SELECT CONCAT(ServiceName, ' - ', ServiceVersion) FROM Service WHERE ServiceID = @oldserv_id),
			(SELECT CONCAT(ServiceName, ' - ', ServiceVersion) FROM Service WHERE ServiceID = @newserv_id),
			@portcheck2, GETDATE());
		END
	END
END;


UPDATE DeviceService
SET ServiceID = 3		--OpenSSH 6.4 (port 22)
WHERE DSID = 2;

UPDATE DeviceService
SET ServiceID = 11		--OpenSSH 9.9p2 (port 22)
WHERE DSID = 2;



--QUERIES (TPI6)
--This query answers the following question:
--How many devices are registered by Nutshell’s users?
SELECT CONCAT(FirstName, ' ', LastName) AS 'User', 
	   COUNT(d.DeviceID) AS DeviceCount 
FROM Account a JOIN Device d ON a.UserID = d.UserID
GROUP BY FirstName, LastName
ORDER BY DeviceCount DESC;


--This query answers the following question:
--How many devices are registered by Nutshell’s users?
SELECT d.MACAddress AS 'Device',
	   COUNT(vs.DeviceID) AS VulnerabilityCount
FROM Device d LEFT JOIN VulnService vs ON d.DeviceID = vs.DeviceID
GROUP BY d.MACAddress
ORDER BY VulnerabilityCount DESC;



--QUERIES (TPI5)
--This query answers this question:
--What active services are running on a specific user’s device?
SELECT a.UserID, a.EmailAddress AS UserEmail, os.OS_Name, d.DeviceType, CONCAT(s.TCPOrUDP, ' Port ', s.ServicePort, ': ', 
																		s.ServiceName, ' ', s.ServiceVersion) AS 'Service'
FROM Account a JOIN Device d ON a.UserID = d.UserID 
JOIN OperatingSystem os ON d.OS_ID = os.OS_ID 
JOIN DeviceService ds ON d.DeviceID = ds.DeviceID 
JOIN Service s ON s.ServiceID = ds.ServiceID
WHERE a.UserID = 1;


SELECT *		--PoC that my query worked
FROM Account a LEFT JOIN Device d ON a.UserID = d.UserID 
LEFT JOIN OperatingSystem os ON d.OS_ID = os.OS_ID 
LEFT JOIN DeviceService ds ON d.DeviceID = ds.DeviceID 
LEFT JOIN Service s ON s.ServiceID = ds.ServiceID;


--This query answers this question:
--How many devices in the database use a Linux kernel?
SELECT 
    os.OS_Name AS 'Operating System',
    COUNT(d.DeviceID) AS 'Devices Using OS',
    COUNT(l.OS_ID) AS 'Available Linux OS',
    COUNT(w.OS_ID) AS 'Available Windows OS',
    COUNT(m.OS_ID) AS 'Available MacOS'
FROM OperatingSystem os
LEFT JOIN Linux l ON os.OS_ID = l.OS_ID
LEFT JOIN Windows w ON os.OS_ID = w.OS_ID
LEFT JOIN MacOS m ON os.OS_ID = m.OS_ID
LEFT JOIN Device d ON d.OS_ID = os.OS_ID
GROUP BY os.OS_Name;


SELECT	*		--PoC that my query worked
FROM OperatingSystem os  LEFT
JOIN Device d ON os.OS_ID = d.OS_ID LEFT
JOIN Linux l ON os.OS_ID = l.OS_ID LEFT
JOIN Windows w ON os.OS_ID = w.OS_ID LEFT
JOIN MacOS m ON os.OS_ID = m.OS_ID; 


--This view will answer the following question:
--How many devices are vulnerable to known exploits, 
--and what are the associated CVSS scores for each vulnerability?
CREATE VIEW Vulnerable_Devices AS
SELECT d.MACAddress AS 'Vulnerable Device',
       CASE 
           WHEN v.OS_ID IS NOT NULL THEN (SELECT os.OS_Name FROM OperatingSystem os WHERE os.OS_ID = v.OS_ID)
           ELSE CONCAT(s.TCPOrUDP, ' Port ', s.ServicePort, ': ', s.ServiceName, ' ', s.ServiceVersion)
       END AS 'Vulnerable Service',
       v.ExploitName AS 'Exploit Name',
       r.CVSSScore
FROM Device d
JOIN VulnService vs ON d.DeviceID = vs.DeviceID
JOIN Vulnerability v ON vs.ExploitID = v.ExploitID
JOIN Risk r ON v.ExploitID = r.ExploitID
left JOIN Service s ON s.ServiceID = vs.ServiceID;

SELECT * FROM Vulnerable_Devices	--PoC that my query worked