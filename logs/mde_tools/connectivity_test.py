import logging
import os
import re
import urllib.request
import ssl
import sys

from mde_tools import constants

log = logging.getLogger(constants.LOGGER_NAME)

sc_verify = """-----BEGIN CERTIFICATE-----
MIIG2DCCBMCgAwIBAgIKYT+3GAAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9z
b2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTExMDE4MjI1
NTE5WhcNMjYxMDE4MjMwNTE5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
cnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgU2VjdXJlIFNlcnZlciBDQSAy
MDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0AvApKgZgeI25eKq
5fOyFVh1vrTlSfHghPm7DWTvhcGBVbjz5/FtQFU9zotq0YST9XV8W6TUdBDKMvMj
067uz54EWMLZR8vRfABBSHEbAWcXGK/G/nMDfuTvQ5zvAXEqH4EmQ3eYVFdznVUr
8J6OfQYOrBtU8yb3+CMIIoueBh03OP1y0srlY8GaWn2ybbNSqW7prrX8izb5nvr2
HFgbl1alEeW3Utu76fBUv7T/LGy4XSbOoArX35Ptf92s8SxzGtkZN1W63SJ4jqHU
mwn4ByIxcbCUruCw5yZEV5CBlxXOYexl4kvxhVIWMvi1eKp+zU3sgyGkqJu+mmoE
4KMczVYYbP1rL0I+4jfycqvQeHNye97sAFjlITCjCDqZ75/D93oWlmW1w4Gv9Dlw
Sa/2qfZqADj5tAgZ4Bo1pVZ2Il9q8mmuPq1YRk24VPaJQUQecrG8EidT0sH/ss1Q
mB619Lu2woI52awb8jsnhGqwxiYL1zoQ57PbfNNWrFNMC/o7MTd02Fkr+QB5GQZ7
/RwdQtRBDS8FDtVrSSP/z834eoLP2jwt3+jYEgQYuh6Id7iYHxAHu8gFfgsJv2vd
405bsPnHhKY7ykyfW2Ip98eiqJWIcCzlwT88UiNPQJrDMYWDL78p8R1QjyGWB87v
8oDCRH2bYu8vw3eJq0VNUz4CedMCAwEAAaOCAUswggFHMBAGCSsGAQQBgjcVAQQD
AgEAMB0GA1UdDgQWBBQ2VollSctbmy88rEIWUE2RuTPXkTAZBgkrBgEEAYI3FAIE
DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
HSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklo
dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29D
ZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEF
BQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29D
ZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQBByGHB
9VuePpEx8bDGvwkBtJ22kHTXCdumLg2fyOd2NEavB2CJTIGzPNX0EjV1wnOl9U2E
jMukXa+/kvYXCFdClXJlBXZ5re7RurguVKNRB6xo6yEM4yWBws0q8sP/z8K9SRia
x/CExfkUvGuV5Zbvs0LSU9VKoBLErhJ2UwlWDp3306ZJiFDyiiyXIKK+TnjvBWW3
S6EWiN4xxwhCJHyke56dvGAAXmKX45P8p/5beyXf5FN/S77mPvDbAXlCHG6FbH22
RDD7pTeSk7Kl7iCtP1PVyfQoa1fB+B1qt1YqtieBHKYtn+f00DGDl6gqtqy+G0H1
5IlfVvvaWtNefVWUEH5TV/RKPUAqyL1nn4ThEO792msVgkn8Rh3/RQZ0nEIU7cU5
07PNC4MnkENRkvJEgq5umhUXshn6x0VsmAF7vzepsIikkrw4OOAd5HyXmBouX+84
Zbc1L71/TyH6xIzSbwb5STXq3yAPJarqYKssH0uJ/Lf6XFSQSz6iKE9s5FJlwf2Q
HIWCiG7pplXdISh5RbAU5QrM5l/Eu9thNGmfrCY498EpQQgVLkyg9/kMPt5fqwgJ
LYOsrDSDYvTJSUKJJbVuskfFszmgsSAbLLGOBG+lMEkc0EbpQFv0rW6624JKhxJK
gAlN2992uQVbG+C7IHBfACXH0w76Fq17Ip5xCA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF7TCCA9WgAwIBAgIQP4vItfyfspZDtWnWbELhRDANBgkqhkiG9w0BAQsFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEw
MzIyMjIwNTI4WhcNMzYwMzIyMjIxMzA0WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
aWNhdGUgQXV0aG9yaXR5IDIwMTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCygEGqNThNE3IyaCJNuLLx/9VSvGzH9dJKjDbu0cJcfoyKrq8TKG/Ac+M6
ztAlqFo6be+ouFmrEyNozQwph9FvgFyPRH9dkAFSWKxRxV8qh9zc2AodwQO5e7BW
6KPeZGHCnvjzfLnsDbVU/ky2ZU+I8JxImQxCCwl8MVkXeQZ4KI2JOkwDJb5xalwL
54RgpJki49KvhKSn+9GY7Qyp3pSJ4Q6g3MDOmT3qCFK7VnnkH4S6Hri0xElcTzFL
h93dBWcmmYDgcRGjuKVB4qRTufcyKYMME782XgSzS0NHL2vikR7TmE/dQgfI6B0S
/Jmpaz6SfsjWaTr8ZL22CZ3K/QwLopt3YEsDlKQwaRLWQi3BQUzK3Kr9j1uDRprZ
/LHR47PJf0h6zSTwQY9cdNCssBAgBkm3xy0hyFfj0IbzA2j70M5xwYmZSmQBbP3s
MJHPQTySx+W6hh1hhMdfgzlirrSSL0fzC/hV66AfWdC7dJse0Hbm8ukG1xDo+mTe
acY1logC8Ea4PyeZb8txiSk190gWAjWP1Xl8TQLPX+uKg09FcYj5qQ1OcunCnAfP
SRtOBA5jUYxe2ADBVSy2xuDCZU7JNDn1nLPEfuhhbhNfFcRf2X7tHc7uROzLLoax
7Dj2cO2rXBPB2Q8Nx4CyVe0096yb5MPa50c8prWPMd/FS6/r8QIDAQABo1EwTzAL
BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUci06AjGQQ7kU
BU7h6qfHMdEjiTQwEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQELBQADggIB
AH9yzw+3xRXbm8BJyiZb/p4T5tPw0tuXX/JLP02zrhmu7deXoKzvqTqjwkGw5biR
nhOBJAPmCf0/V0A5ISRW0RAvS0CpNoZLtFNXmvvxfomPEf4YbFGq6O0JlbXlccmh
6Yd1phV/yX43VF50k8XDZ8wNT2uoFwxtCJJ+i92Bqi1wIcM9BhS7vyRep4TXPw8h
Ir1LAAbblxzYXtTFC1yHblCk6MM4pPvLLMWSZpuFXst6bJN8gClYW1e1QGm6CHmm
ZGIVnYeWRbVmIyADixxzoNOieTPgUFmG2y/lAiXqcyqfABTINseSO+lOAOzYVgm5
M0kS0lQLAausR7aRKX1MtHWAUgHoyoL2n8ysnI8X6i8msKtyrAv+nlEex0NVZ09R
s1fWtuzuUrc66U7h14GIvE+OdbtLqPA1qibUZ2dJsnBMO5PcHd94kIZysjik0dyS
TclY6ysSXNQ7roxrsIPlAT/4CTL2kzU0Iq/dNw13CYArzUgA8YyZGUcFAenRv9FO
0OYoQzeZpApKCNmacXPSqs0xE2N2oTdvkjgefRI8ZjLny23h/FKJ3crWZgWalmG+
oijHHKOnNlA8OqTfSm7mhzvO6/DggTedEzxSjr25HTTGHdUKaj2YKXCMiSrRq4IQ
SB/c9O+lxbtVGjhjhE63bK2VVOxlIhBJF7jAHscPrFRH
-----END CERTIFICATE-----
"""
digi = """-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----
"""

urls_map = {
    "GW_US": [
        { "url" :"https://mdav.us.endpoint.security.microsoft.com/mdav/test", "verify": [ sc_verify ], "expected_status_code": 404, "http_method": "GET" },
        { "url" :"https://mdav.us.endpoint.security.microsoft.com/storage/ussus1eastprod/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://mdav.us.endpoint.security.microsoft.com/storage/ussus1westprod/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://mdav.us.endpoint.security.microsoft.com/xplat/api/report", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://mdav.us.endpoint.security.microsoft.com/packages/?ostype=mac", "verify": [ sc_verify, digi ], "expected_status_code": 200, "http_method": "HEAD" },
        { "url" :"https://edr-cus.us.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-eus.us.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-cus3.us.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-eus3.us.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-cus.us.endpoint.security.microsoft.com/storage/automatedirstrprdcus/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://edr-eus.us.endpoint.security.microsoft.com/storage/automatedirstrprdeus/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://edr-cus3.us.endpoint.security.microsoft.com/storage/automatedirstrprdcus3/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://edr-eus3.us.endpoint.security.microsoft.com/storage/automatedirstrprdeus3/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
    ],
    "GW_EU": [
        { "url" :"https://mdav.eu.endpoint.security.microsoft.com/mdav/test", "verify": [ sc_verify ], "expected_status_code": 404, "http_method": "GET" },
        { "url" :"https://mdav.eu.endpoint.security.microsoft.com/storage/usseu1northprod/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://mdav.eu.endpoint.security.microsoft.com/storage/usseu1westprod/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://mdav.eu.endpoint.security.microsoft.com/xplat/api/report", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://mdav.eu.endpoint.security.microsoft.com/packages/?ostype=mac", "verify": [ sc_verify, digi ], "expected_status_code": 200, "http_method": "HEAD" },
        { "url" :"https://edr-weu.eu.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-neu.eu.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-weu3.eu.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-neu3.eu.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-weu.eu.endpoint.security.microsoft.com/storage/automatedirstrprdweu/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://edr-neu.eu.endpoint.security.microsoft.com/storage/automatedirstrprdneu/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://edr-weu3.eu.endpoint.security.microsoft.com/storage/automatedirstrprdweu3/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://edr-neu3.eu.endpoint.security.microsoft.com/storage/automatedirstrprdneu3/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
    ],
    "GW_UK": [
        { "url" :"https://mdav.uk.endpoint.security.microsoft.com/mdav/test", "verify": [ sc_verify ], "expected_status_code": 404, "http_method": "GET" },
        { "url" :"https://mdav.uk.endpoint.security.microsoft.com/storage/ussuk1southprod/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://mdav.uk.endpoint.security.microsoft.com/storage/ussuk1westprod/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://mdav.uk.endpoint.security.microsoft.com/xplat/api/report", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://mdav.uk.endpoint.security.microsoft.com/packages/?ostype=mac", "verify": [ sc_verify, digi ], "expected_status_code": 200, "http_method": "HEAD" },
        { "url" :"https://edr-uks.uk.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-ukw.uk.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-uks.uk.endpoint.security.microsoft.com/storage/automatedirstrprduks/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://edr-ukw.uk.endpoint.security.microsoft.com/storage/automatedirstrprdukw/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
    ],
    "GW_AU": [
        { "url" :"https://mdav.au.endpoint.security.microsoft.com/mdav/test", "verify": [ sc_verify ], "expected_status_code": 404, "http_method": "GET" },
        { "url" :"https://mdav.au.endpoint.security.microsoft.com/storage/ussau1eastprod/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://mdav.au.endpoint.security.microsoft.com/storage/ussau1southeastprod/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://mdav.au.endpoint.security.microsoft.com/xplat/api/report", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://mdav.au.endpoint.security.microsoft.com/packages/?ostype=mac", "verify": [ sc_verify, digi ], "expected_status_code": 200, "http_method": "HEAD" },
        { "url" :"https://edr-aus.au.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-aue.au.endpoint.security.microsoft.com/edr/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://edr-aus.au.endpoint.security.microsoft.com/storage/automatedirstrprdaus/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://edr-aue.au.endpoint.security.microsoft.com/storage/automatedirstrprdaue/", "verify": [ sc_verify ], "expected_status_code": 400, "http_method": "GET" },
    ],
    "US": [
        { "url" :"https://unitedstates.cp.wd.microsoft.com/wdcp.svc/bond/submitReport/test", "verify": [ sc_verify ], "expected_status_code": 404, "http_method": "GET" },
        { "url" :"https://ussus1eastprod.blob.core.windows.net/", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://ussus1westprod.blob.core.windows.net/", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://unitedstates.x.cp.wd.microsoft.com/api/report", "verify": None, "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://go.microsoft.com/fwlink/?linkid=2120136", "verify": None, "expected_status_code": 200, "http_method": "HEAD" },
        { "url" :"https://winatp-gw-cus.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://winatp-gw-eus.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://winatp-gw-cus3.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://winatp-gw-eus3.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://automatedirstrprdcus.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://automatedirstrprdeus.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://automatedirstrprdcus3.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://automatedirstrprdeus3.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
    ],
    "EU": [
        { "url" :"https://europe.cp.wd.microsoft.com/wdcp.svc/bond/submitReport/test", "verify": [ sc_verify ], "expected_status_code": 404, "http_method": "GET" },
        { "url" :"https://usseu1northprod.blob.core.windows.net/", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://usseu1westprod.blob.core.windows.net/", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://europe.x.cp.wd.microsoft.com/api/report", "verify": None, "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://go.microsoft.com/fwlink/?linkid=2120136", "verify": None, "expected_status_code": 200, "http_method": "HEAD" },
        { "url" :"https://winatp-gw-weu.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://winatp-gw-neu.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://winatp-gw-weu3.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://winatp-gw-neu3.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://automatedirstrprdneu.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://automatedirstrprdweu.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://automatedirstrprdneu3.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://automatedirstrprdweu3.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
    ],
    "UK": [
        { "url" :"https://unitedkingdom.cp.wd.microsoft.com/wdcp.svc/bond/submitReport/test", "verify": [ sc_verify ], "expected_status_code": 404, "http_method": "GET" },
        { "url" :"https://ussuk1southprod.blob.core.windows.net/", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://ussuk1westprod.blob.core.windows.net/", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://unitedkingdom.x.cp.wd.microsoft.com/api/report", "verify": None, "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://go.microsoft.com/fwlink/?linkid=2120136", "verify": None, "expected_status_code": 200, "http_method": "HEAD" },
        { "url" :"https://winatp-gw-ukw.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://winatp-gw-uks.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://automatedirstrprdukw.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://automatedirstrprduks.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
    ],
    "AU": [
        { "url" :"https://australia.cp.wd.microsoft.com/wdcp.svc/bond/submitReport/test", "verify": [ sc_verify ], "expected_status_code": 404, "http_method": "GET" },
        { "url" :"https://ussau1eastprod.blob.core.windows.net/", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://ussau1southeastprod.blob.core.windows.net/", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://australia.x.cp.wd.microsoft.com/api/report", "verify": None, "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://go.microsoft.com/fwlink/?linkid=2120136", "verify": None, "expected_status_code": 200, "http_method": "HEAD" },
        { "url" :"https://winatp-gw-aus.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://winatp-gw-aue.microsoft.com/commands/test", "verify": [ sc_verify ], "expected_status_code": 200, "http_method": "GET" },
        { "url" :"https://automatedirstrprdaus.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
        { "url" :"https://automatedirstrprdaue.blob.core.windows.net", "verify": None, "expected_status_code": 400, "http_method": "GET" },
    ]
}

def log_error_and_exit(message):
    log.error(message)
    sys.exit(1)

def connectivity_test(case):
    try:
        if case['verify'] != None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            for ca in case['verify']:
                context.load_verify_locations(cadata=ca)
        else:
            context = ssl.create_default_context(cadata=case['verify'])

        if case['http_method'] == "GET":
            response_internal = urllib.request.urlopen(case['url'], context=context)
            response = response_internal.status
        elif case['http_method'] == "HEAD":
            req = urllib.request.Request(case['url'], method="HEAD")
            response_internal = urllib.request.urlopen(req, context=context)
            response = response_internal.status
        else:
            print("Please implement " + case['http_method'])
        
        return { "response": response, "error": None }
    except Exception as e:
        if isinstance(e, urllib.request.HTTPError):
            return { "response": e.code, "error": None }
        elif isinstance(e, urllib.error.URLError):
            if ("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed" in str(e.reason)):
                return { "response": None, "error": "SSL cert issue" }
            elif ("[Errno 8] nodename nor servname provided, or not known" in str(e.reason)):
                return { "response": None, "error": "Request timeout" }
        else:
            return { "response": None, "error": "Request general issue" }

def get_geo_from_onboarding(onboarding_path):
    if os.path.exists(onboarding_path):
        with open(onboarding_path, 'r') as file:
            contenido = file.read()

        simplified = r'GW_.*?"'
        legacy_mac = r'vortexGeoLocation\\\":\\\"(.*?)\\\"'
        legacy_linux = r'"vortexGeoLocation\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"(.*?)\\\\\\\\\\\\\\\"'
        resultado_s = re.findall(simplified, contenido)
        resultado_lm = re.findall(legacy_mac, contenido)
        resultado_ll = re.findall(legacy_linux, contenido)

        if resultado_s:
            primer_resultado = resultado_s[0]
            primer_resultado = primer_resultado.replace('\\', '')
            primer_resultado = primer_resultado.replace('"', '')
            return primer_resultado
        elif resultado_lm:
            return resultado_lm[0]
        elif resultado_ll:
            return resultado_ll[0]
        else:
            log_error_and_exit("Onboarding file is not compatible")
    else :
        log_error_and_exit(f"Onboarding script {onboarding_path} does not exist")

def check_key(key):
    if key not in urls_map:
        log_error_and_exit(f"Geo {key} not supported")

def perform_test(geo, onboarding_path):
    key = ""
    if geo != None:
        key = geo
    elif onboarding_path != None:
        key = get_geo_from_onboarding(onboarding_path)
    else:
        log_error_and_exit("Please provide geo to test")

    check_key(key)

    for case in urls_map[key]:
        result = connectivity_test(case)
        if result['response'] != None and result['response'] == case['expected_status_code']:
            log.info(f"Testing connection with {case['url']} ... [OK]")
        else:
            log.info(f"Testing connection with {case['url']} ... [ERROR]")
            if result['error'] != None:
                log.info(f"\t {str(result['error'])}")
            else:
                log.error(f"\t response {result['response']}")
