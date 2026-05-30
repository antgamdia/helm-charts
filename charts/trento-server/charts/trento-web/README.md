# trento-web

![Version: 3.1.0](https://img.shields.io/badge/Version-3.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square)

Trento Web Chart

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| adminUser.password | string | `""` |  |
| adminUser.username | string | `"admin"` |  |
| affinity | object | `{}` |  |
| alerting.enabled | string | `nil` |  |
| alerting.recipient | string | `nil` |  |
| alerting.sender | string | `nil` |  |
| alerting.smtpPassword | string | `nil` |  |
| alerting.smtpPort | string | `nil` |  |
| alerting.smtpServer | string | `nil` |  |
| alerting.smtpUser | string | `nil` |  |
| autoscaling.enabled | bool | `false` |  |
| autoscaling.maxReplicas | int | `100` |  |
| autoscaling.minReplicas | int | `1` |  |
| autoscaling.targetCPUUtilizationPercentage | int | `80` |  |
| chartsEnabled | bool | `true` |  |
| fullnameOverride | string | `""` |  |
| global.logLevel | string | `"info"` |  |
| global.postgresql.name | string | `"postgresql"` |  |
| global.postgresql.postgresqlPassword | string | `""` |  |
| global.postgresql.postgresqlUsername | string | `""` |  |
| global.postgresql.servicePort | int | `5432` |  |
| global.prometheus.name | string | `"prometheus-server"` |  |
| global.rabbitmq.auth.password | string | `""` |  |
| global.rabbitmq.auth.tls.enabled | bool | `false` |  |
| global.rabbitmq.auth.username | string | `""` |  |
| global.rabbitmq.name | string | `""` |  |
| global.rabbitmq.servicePort | string | `""` |  |
| global.trentoWeb.name | string | `""` |  |
| global.trentoWeb.origin | string | `""` |  |
| global.trentoWeb.servicePort | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"ghcr.io/trento-project/trento-web"` |  |
| image.tag | string | `"3.1.0"` |  |
| imagePullSecrets | list | `[]` |  |
| ingress.annotations."kubernetes.io/tls-acme" | string | `"true"` |  |
| ingress.className | string | `"traefik"` |  |
| ingress.enabled | bool | `true` |  |
| ingress.hosts[0].host | string | `""` |  |
| ingress.hosts[0].paths[0].path | string | `"/"` |  |
| ingress.hosts[0].paths[0].pathType | string | `"ImplementationSpecific"` |  |
| ingress.tls | list | `[]` |  |
| nameOverride | string | `""` |  |
| nodeSelector | object | `{}` |  |
| oauth2.authorizeUrl | string | `""` |  |
| oauth2.baseUrl | string | `""` |  |
| oauth2.clientId | string | `""` |  |
| oauth2.clientSecret | string | `""` |  |
| oauth2.enabled | bool | `false` |  |
| oauth2.scopes | string | `"profile email"` |  |
| oauth2.tokenUrl | string | `""` |  |
| oauth2.userUrl | string | `""` |  |
| oidc.baseUrl | string | `""` |  |
| oidc.clientId | string | `""` |  |
| oidc.clientSecret | string | `""` |  |
| oidc.enabled | bool | `false` |  |
| podAnnotations | object | `{}` |  |
| podSecurityContext | object | `{}` |  |
| postgresql.image.registry | string | `"registry.suse.com"` |  |
| postgresql.image.repository | string | `"suse/postgres"` |  |
| postgresql.image.tag | string | `"14"` |  |
| pruneEventsCronjobSchedule | string | `"0 0 * * *"` |  |
| pruneEventsOlderThan | int | `10` |  |
| replicaCount | int | `1` |  |
| resources | object | `{}` |  |
| saml.emailAttrName | string | `"email"` |  |
| saml.enabled | bool | `false` |  |
| saml.firstNameAttrName | string | `"firstName"` |  |
| saml.idpId | string | `""` |  |
| saml.idpNameIdFormat | string | `"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"` |  |
| saml.lastNameAttrName | string | `"lastName"` |  |
| saml.metadataContent | string | `""` |  |
| saml.metadataUrl | string | `""` |  |
| saml.signMetadata | bool | `true` |  |
| saml.signRequests | bool | `true` |  |
| saml.signedAssertion | bool | `true` |  |
| saml.signedEnvelopes | bool | `true` |  |
| saml.spContactEmail | string | `"admin@trento.suse.com"` |  |
| saml.spContactName | string | `"Trento SP Admin"` |  |
| saml.spDir | string | `"/etc/trento/saml"` |  |
| saml.spEntityId | string | `""` |  |
| saml.spId | string | `""` |  |
| saml.spOrgDisplayName | string | `"SAML SP build with Trento"` |  |
| saml.spOrgName | string | `"Trento SP"` |  |
| saml.spOrgUrl | string | `"https://www.trento-project.io/"` |  |
| saml.usernameAttrName | string | `"username"` |  |
| secretKeyBase | string | `""` |  |
| securityContext | object | `{}` |  |
| service.port | int | `4000` |  |
| service.type | string | `"ClusterIP"` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| tolerations | list | `[]` |  |
| trentoWebOrigin | string | `""` |  |

