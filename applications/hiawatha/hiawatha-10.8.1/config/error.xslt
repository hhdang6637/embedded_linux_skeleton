<?xml version="1.0" ?>
<xsl:stylesheet version="1.1" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="html" doctype-system="about:legacy-compat" />

<xsl:template match="/error">
<html>

<head>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title><xsl:value-of select="code" /> - <xsl:value-of select="message" /></title>
<style type="text/css">
	body {
		background-color:#d0d0d0;
		font-family:sans-serif;
		padding:0 30px;
	}

	div {
		background-color:#f8f8f8;
		letter-spacing:4px;
		max-width:400px;
		margin:100px auto 0 auto;
		padding:50px;
		border-radius:10px;
		border:1px solid #808080;
		box-shadow:8px 15px 20px #404040
	}

	h1 {
		margin:0;
		font-size:22px;
		font-weight:normal
	}

	p {
		margin:10px 0 0 0;
		padding-top:2px;
		font-size:14px;
		color:#606060;
		border-top:1px solid #a0a0ff;
		text-align:right;
		font-weight:bold
	}

	@media (max-width:767px) {
		h1 {
			font-size:90%;
			letter-spacing:2px;
		}

		p {
			font-size:70%;
		}
	}
</style>
</head>

<body>
<div>
<h1><xsl:value-of select="message" /></h1>
<p><xsl:value-of select="code" /></p>
</div>
</body>

</html>
</xsl:template>

</xsl:stylesheet>
