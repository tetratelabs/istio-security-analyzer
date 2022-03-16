<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Istio Security Scanning Report</title>
  </head>
  <body>
  <h2> Config Warnings </h2>
  {{range .ConfigWarnings}}
    <div>
      {{ .  }}
    </div>
  {{end}}

  <h2> CVE Report </h2>
  {{range .Vunerabilities}}
    <div>
      {{ .DisclosureID  }}
    </div>
  {{end}}
  </body>
</html>
