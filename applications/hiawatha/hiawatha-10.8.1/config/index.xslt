<?xml version="1.0" ?>
<xsl:stylesheet version="1.1" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="html" doctype-system="about:legacy-compat" />

<xsl:template match="/index">
<html>

<head>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title><xsl:value-of select="hostname" /> : <xsl:value-of select="request_uri" /></title>
<style type="text/css">
	body {
		background-color:#ffffff;
		font-family:sans-serif;
		font-size:12px;
		padding:25px 100px;
	}

	h1 {
		font-size:200%;
		letter-spacing:5px;
		max-width:800px;
		margin:15px auto;
	}

	table {
		width:100%;
		max-width:800px;
		margin:0 auto;
		padding:20px;
		border-spacing:0;
		border:1px solid #c0c0c0;
		background-color:#f4f4f4;
		border-radius:15px;
		box-shadow:6px 12px 10px #808080;
	}

	thead th {
		border-bottom:2px solid #e0e0e0;
		letter-spacing:1px;
	}
	thead th.timestamp {
		width:175px;
	}
	thead th.size {
		width:140px;
	}

	tbody td {
		border-bottom:1px solid #e0e0e0;
		padding:2px 15px;
	}
	tbody tr:hover td {
		background-color:#ffffc0;
		cursor:pointer;
	}
	tbody tr:nth-child(even) {
		background-color:#e8e8f0;
	}
	tbody tr:nth-child(odd) {
		background-color:#f0f0f8;
	}
	tbody td.size {
		text-align:right;
	}
	tbody td.dir a {
		color:#0000ff;
	}
	tbody td.file a {
		color:#4080ff;
	}

	tfoot td {
		padding:20px 15px 0 15px;
	}
	tfoot td.totalsize {
		text-align:right;
	}

	a {
		text-decoration:none;
	}

	div.powered {
		margin-top:40px;
		text-align:center;
		color:#808080;
	}
	div.powered a {
		color:#80b0c0;
	}

	@media (max-width:767px) {
		body {
			padding:25px;
		}

		h1 {
			font-size:160%;
			letter-spacing:3px;
		}

		tbody td {
			padding:5px 15px;
		}
	}

	@media (max-width:511px) {
		h1 {
			font-size:130%;
			letter-spacing:1px;
		}

		table th:nth-child(2),
		table td:nth-child(2) {
			display:none;
		}
	}
</style>
</head>

<body>
<h1><xsl:value-of select="hostname" /> : <xsl:value-of select="request_uri" /></h1>
<table>
<thead>
<tr>
	<th class="filename">filename</th>
	<th class="timestamp">timestamp</th>
	<th class="size">filesize</th>
</tr>
</thead>
<tbody>
<xsl:for-each select="files/file">
<tr onClick="javascript:window.location.href='{.}'">
	<td class="{@type}"><a href="{@url_encoded}"><xsl:value-of select="." /></a></td>
	<td><xsl:value-of select="@timestamp" /></td>
	<td class="size"><xsl:value-of select="@size" /></td>
</tr>
</xsl:for-each>
</tbody>
<tfoot>
<tr>
	<td class="totalfiles"><xsl:value-of select="count(files/file)" /> files</td>
	<td></td>
	<td class="totalsize"><xsl:value-of select="total_size" /></td>
</tr>
</tfoot>
</table>
<div class="powered">Powered by <a href="https://www.hiawatha-webserver.org/" target="_blank"><xsl:value-of select="software" /></a></div>
</body>

</html>
</xsl:template>

</xsl:stylesheet>
