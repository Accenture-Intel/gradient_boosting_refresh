<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/">
		<html>
			<head>
				<title>MDE Client Analyzer Results</title>
				<style>
					h1 { font-family: "Segoe UI", Frutiger, "Frutiger Linotype", "Dejavu Sans", "Helvetica Neue", Arial, sans-serif; font-size: 32px; font-style: normal; font-variant: normal; font-weight: 700; line-height: 26.4px; }
					h3 { font-family: "Segoe UI", Frutiger, "Frutiger Linotype", "Dejavu Sans", "Helvetica Neue", Arial, sans-serif; font-size: 24px; font-style: normal; font-variant: normal; font-weight: 700; line-height: 15.4px; }
					p { font-family: "Segoe UI", Frutiger, "Frutiger Linotype", "Dejavu Sans", "Helvetica Neue", Arial, sans-serif; font-size: 14px; font-style: normal; font-variant: normal; font-weight: 400; line-height: 20px; }

					.DeviceTable {
						table-layout: fixed;
						border-spacing: 0;
						display: table;
						border-collapse: collapse;
						box-sizing: border-box;
						border-color: grey;
						border: 1px solid #ddd;		
						width: auto;
					}

					table {
						display: table;
						font-family: Segoe UI,Frutiger,Frutiger Linotype,Dejavu Sans,Helvetica Neue,Arial,sans-serif; 
						font-size: 14px;
						padding: 10px;
						border: 1px solid black;
						border-collapse: collapse;
						border-collapse: collapse;
						border-spacing: 0;
						border: 1px solid #ddd;		
						width: 90%;
					}

					th, td {
					  text-align: left;
					  padding: 8px;
					}
					tr:nth-child(even){background-color: #f2f2f2}

					*, :after, :before {
						box-sizing: border-box;
					}
					.event-severity {
						position: relative;
						padding-left: 34px;
						display: inline-block;
						line-height: 14px;
						height: 14px;
					}
					.event-severity:before {
						content: '';
						display: block;
						position: absolute;
						left: 0;
						top: 0;
						height: 8px;
						transform: translateY(50%);
						width: 26px;
						background: repeating-linear-gradient(to right,#d9d9d9,#d9d9d9 8px,transparent 8px,transparent 9px);
					}
					.event-severity:after {
						content: '';
						display: block;
						position: absolute;
						left: 0;
						top: 0;
						height: 8px;
						transform: translateY(50%);
					}
					.event-severity.event-severity-high:after {
						width: 26px;
						background: repeating-linear-gradient(to right,#900,#900 8px,transparent 8px,transparent 9px);
					}
					.event-severity.event-severity-low:after {
						width: 8px;
						background: repeating-linear-gradient(to right,#f56a00,#f56a00 8px,transparent 8px,transparent 9px);
					}
					.event-severity.event-severity-informational:after {
						width: -1px;
						background: repeating-linear-gradient(to right,#d9d9d9,#d9d9d9 8px,transparent 8px,transparent 9px);
					}
					.event-severity.event-severity-medium:after {
						width: 17px;
						background: repeating-linear-gradient(to right,#f56a00,#f56a00 8px,transparent 8px,transparent 9px);
					}		
				</style>
				
			</head>
			<body>
				<h1>Microsoft Defender for Endpoint Client Analyzer Results</h1>
				<xsl:apply-templates/>
			</body>
		</html>
	</xsl:template>
	<xsl:template match="mdatp/general">
		<div>
			<p><b>Script version: </b><xsl:value-of select="script_version"/> | <b>Runtime: </b><xsl:value-of select="script_run_time"/></p>
			<br></br>
		</div>	
	</xsl:template>		
	<xsl:template match="mdatp/device_info">
		<div>
			<h3>Device Information</h3>
			<table class="DeviceTable">
					<xsl:for-each select="./*">
						<xsl:if test=". != ''">
							<tr>
								<th width="350px"><xsl:value-of select="./@display_name"/></th>
								<td>
								<xsl:choose>
									<xsl:when test=". = 'Running'">
										<span style="color:green"><xsl:value-of select="."></xsl:value-of></span>
									</xsl:when>
									<xsl:when test=". = 'Error'">
										<span style="color:red"><xsl:value-of select="."></xsl:value-of></span>
									</xsl:when>
									<xsl:otherwise>
										<xsl:value-of select="."></xsl:value-of>
									</xsl:otherwise>
								</xsl:choose>
								</td>
							</tr>
						</xsl:if>
					</xsl:for-each>
			</table>
		</div>
	<br></br><br></br>
	</xsl:template>
	
	<xsl:template match="mdatp/events">
		<hr></hr>
		<div>
			<h3>Checks Results</h3>
			<table>
				<tr>
					<th width="120px">Category</th>
					<th width="120px">Severity</th>
					<th width="80px">Id</th>
					<th width="120px">Check Name</th>
					<th>Results</th>
					<th>Comments</th>
				</tr>
				<xsl:for-each select="event">
					<xsl:sort select="substring(@id,3,1)" order="descending"/> <!-- Sort by the second digit of the event ID (Severity) -->
					<tr>
						<td>
							<xsl:choose>
								<xsl:when test="substring(@id, 2, 1) = '1'">Environment</xsl:when>
								<xsl:when test="substring(@id, 2, 1) = '2'">Configuration</xsl:when>
								<xsl:when test="substring(@id, 2, 1) = '3'">Connectivity</xsl:when>
								<xsl:when test="substring(@id, 2, 1) = '4'">Telemetry</xsl:when>
                        	</xsl:choose>
						</td>
						<td>
							<xsl:choose>
                            	<xsl:when test="substring(@id, 3, 1) = '2'">
									<span class="event-severity event-severity-high"><span>Error</span></span>
								</xsl:when>
							</xsl:choose>
							<xsl:choose>
									<xsl:when test="substring(@id, 3, 1) = '1'">
										<span class="event-severity event-severity-medium"><span>Warning</span></span>
									</xsl:when>
							</xsl:choose>
							<xsl:choose>
									<xsl:when test="substring(@id, 3, 1) = '0'">
										<span class="event-severity event-severity-informational"><span>Informational</span></span>
									</xsl:when>
							</xsl:choose>
						</td>
						<td><xsl:value-of select="@id"/></td>
						<td><xsl:copy-of select="document('events.xml')/events/event[@id = current()/@id]/check_name"/></td>
						<td><xsl:copy-of select="document('events.xml')/events/event[@id = current()/@id]/tsg"/></td>
						<td>N/A</td>
					</tr>
				</xsl:for-each>
			</table>
		</div>
	</xsl:template>
</xsl:stylesheet>
