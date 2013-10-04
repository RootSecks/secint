#!/usr/bin/python

class Server():

	def index(self, **args):
		
		pageText = ("<html><head>"		
			"<script type=\"text/javascript\" src=\"./jsgl.js\"></script>"
			"</head>"
			"<body>"
			"<div id=\"panel\" style=\"width: 1024px; height: 50px\"></div>"
			"<script type=\"text/javascript\">"
			"myPanel = new jsgl.Panel(document.getElementById(\"panel\"));")
		
		
		tmpHostList = get_scan_hosts()
		hostList = list()
		for host in tmpHostList:
			if host.hoststatus == "up":
				hostList.append(host)

		hostNum = len(hostList)
		hostWidth = 1024/hostNum
		
		hostCounter = 0
		for host in hostList:

			if host.hostname == "0":
				host.hostname = "unknown"
			
			tmpServiceList = get_scan_services(host.hostipaddr)
				
			pageText = pageText + ("var host" + str(hostCounter) + " = myPanel.createRectangle();"
					"host" + str(hostCounter) + ".setWidth(" + str(hostWidth - 5) + ");"
					"host" + str(hostCounter) + ".setHeight(25);"
					"host" + str(hostCounter) + ".setX(" + str(hostWidth * hostCounter) + ");"
					"host" + str(hostCounter) + ".setY(0);"
					"host" + str(hostCounter) + ".getFill().setColor('rgb(255,0,0)');"
					"myPanel.addElement(host" + str(hostCounter) + ");"
					"var derp" + str(hostCounter) + " = function() {"
					"document.getElementById('hostservice').innerHTML = '"
					"HostIP: " + host.hostipaddr + "<br>"
					"HostName: " + host.hostname + "<br>"
					"HostOS: " + host.hostos + "<br><br>"
					"Services Detected: <br><br>"
					"<table border=\"1\">"
					"<tr>"
					"<td>ServicePort</td>"
					"<td>ServiceProto</td>"
					"<td>ServiceID</td>"
					"<td>ServiceName</td>"
					"<td>SerivceProduct</td>"
					"<td>ServiceVersion</td>"
					"</tr>")

			for svc in tmpServiceList:
				pageText = pageText + ("<tr><td>" + svc.serviceport + "</td>"
						"<td>" + svc.serviceproto + "</td>"
						"<td>" + svc.serviceid + "</td>"
						"<td>" + svc.servicename + "</td>"
						"<td>" + svc.serviceproduct + "</td>"
						"<td>" + svc.serviceversion + "</td>"
						"</tr>")
			
			pageText = pageText + "</table>"		
			pageText = pageText + ("';"
					"};"
					"var lerp" + str(hostCounter) + " = function() {"
					"document.getElementById('hostservice').innerHTML = ' ';"
					"};"
					"host" + str(hostCounter) + ".addMouseOverListener(derp" + str(hostCounter) + ");"
					"host" + str(hostCounter) + ".addMouseOutListener(lerp" + str(hostCounter) + ");")								
			hostCounter = hostCounter + 1

		pageText = pageText + "</script>"		
		
		pageText = pageText + "<div id=\"hostservice\"></div>"
		
		if not args:
			print "LERP"
		else:
			if 'd' in args:
				pageText = pageText + "d Arg"

		pageText = pageText + '</body></html>'	
		return pageText
	
	index.exposed = True

	def jsgl_js( self ):
		fileHandle = open('jsgl.js')
		fileContents = fileHandle.read()
		return fileContents
	jsgl_js.exposed = True