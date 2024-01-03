<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/">
		<html>
			<head>
				<title>MDE eps top events report</title>
				<style>
					h1 { font-family: "Segoe UI", Frutiger, "Frutiger Linotype", "Dejavu Sans", "Helvetica Neue", Arial, sans-serif; font-size: 32px; font-style: normal; font-variant: normal; font-weight: 700; line-height: 26.4px; }
					h3 { font-family: "Segoe UI", Frutiger, "Frutiger Linotype", "Dejavu Sans", "Helvetica Neue", Arial, sans-serif; font-size: 24px; font-style: normal; font-variant: normal; font-weight: 700; line-height: 15.4px; }
					p { font-family: "Segoe UI", Frutiger, "Frutiger Linotype", "Dejavu Sans", "Helvetica Neue", Arial, sans-serif; font-size: 14px; font-style: normal; font-variant: normal; font-weight: 400; line-height: 20px; }

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
				</style>

			</head>
			<body>
				<h1>Microsoft Defender EPS Module Top Events Report</h1>
				<xsl:apply-templates/>
			</body>
		</html>
	</xsl:template>

	<xsl:template match="eps/general">
		<div>
			<p><b>Sampling Start time: </b><xsl:value-of select="start_time"/> | <b>Sampling Finish time: </b><xsl:value-of select="finish_time"/></p>
			<p><b>Total Event Count: </b><xsl:value-of select="event_count"/></p>
			<br></br>
		</div>
	</xsl:template>

	<xsl:template match="eps/eventtypes">
		<div>
			<h3>Event Types</h3>
			<table class="table">
				<tr>
					<th width="120px">Count</th>
					<th>Type</th>
				</tr>
				<xsl:for-each select="type">
					<tr>
						<td><xsl:value-of select="@count"/></td>
						<td><xsl:value-of select="@name"/></td>
					</tr>
				</xsl:for-each>
			</table>
		</div>
	<br></br><br></br>
	</xsl:template>

	<xsl:template match="eps/topnpid">
		<div>
			<h3>Top Event Process Ids</h3>
			<table class="table">
				<tr>
					<th width="120px">Count</th>
					<th width="120px">PID</th>
					<th>Command</th>
				</tr>
				<xsl:for-each select="process">
					<tr>
						<td><xsl:value-of select="@count"/></td>
						<td><xsl:value-of select="@pid"/></td>
						<td><xsl:value-of select="@command"/></td>
					</tr>
				</xsl:for-each>
			</table>
		</div>
	<br></br><br></br>
	</xsl:template>

	<xsl:template match="eps/topnsid">
		<div>
			<h3>Top Event App Singing Ids</h3>
			<table class="table">
				<tr>
					<th width="120px">Count</th>
					<th>App Singing Id</th>
				</tr>
				<xsl:for-each select="appid">
					<tr>
						<td><xsl:value-of select="@count"/></td>
						<td><xsl:value-of select="@appid"/></td>
					</tr>
				</xsl:for-each>
			</table>
		</div>
	<br></br><br></br>
	</xsl:template>

	<xsl:template match="eps/topnexe">
		<div>
			<h3>Top Event Executables</h3>
			<table class="table">
				<tr>
					<th width="120px">Count</th>
					<th>Path</th>
				</tr>
				<xsl:for-each select="exe">
					<tr>
						<td><xsl:value-of select="@count"/></td>
						<td><xsl:value-of select="@path"/></td>
					</tr>
				</xsl:for-each>
			</table>
		</div>
	<br></br><br></br>
	</xsl:template>

	<xsl:template match="eps/topncdhash">
		<div>
			<h3>Top Event Code Directory Hashes</h3>
			<table class="table">
				<tr>
					<th width="120px">Count</th>
					<th>cdhash</th>
				</tr>
				<xsl:for-each select="cdhash">
					<tr>
						<td><xsl:value-of select="@count"/></td>
						<td><xsl:value-of select="@cdhash"/></td>
					</tr>
				</xsl:for-each>
			</table>
		</div>
	<br></br><br></br>
	</xsl:template>

	<xsl:template match="eps/executables">
		<div>
			<h3>Executables Info:</h3>
			<table class="table">
				<tr>
					<th>App Id</th>
					<th>Team Id</th>
					<th>Path/cdhash</th>
					<th>Is Platform Binary</th>
					<th>Is ES client</th>
					<th>Codesigning_flags</th>
					<th>PIDs and Counts</th>
				</tr>
				<xsl:for-each select="executable">
					<tr>
						<td><xsl:value-of select="@app_id"/></td>
						<td><xsl:value-of select="@team_id"/></td>
						<td><xsl:value-of select="@path"/><br/><xsl:value-of select="@cdhash"/></td>
						<td><xsl:value-of select="@is_os_bin"/></td>
						<td><xsl:value-of select="@is_es_client"/></td>
						<td><xsl:value-of select="@cs_flags"/></td>
						<td><xsl:value-of select="@pids"/></td>
					</tr>
				</xsl:for-each>
			</table>
		</div>
	<br></br><br></br>
	</xsl:template>

</xsl:stylesheet>
