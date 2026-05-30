# trento-wanda

![Version: 2.1.0](https://img.shields.io/badge/Version-2.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square)

Trento Wanda chart

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| autoscaling.enabled | bool | `false` |  |
| autoscaling.maxReplicas | int | `100` |  |
| autoscaling.minReplicas | int | `1` |  |
| autoscaling.targetCPUUtilizationPercentage | int | `80` |  |
| checks.image.pullPolicy | string | `"IfNotPresent"` |  |
| checks.image.repository | string | `"ghcr.io/trento-project/checks"` |  |
| checks.image.tag | string | `"1.3.0"` |  |
| cors.enabled | bool | `false` |  |
| cors.origin | string | `""` |  |
| fullnameOverride | string | `""` |  |
| global.postgresql.name | string | `"postgresql"` |  |
| global.postgresql.postgresqlPassword | string | `""` |  |
| global.postgresql.postgresqlUsername | string | `""` |  |
| global.postgresql.servicePort | int | `5432` |  |
| global.rabbitmq.auth.password | string | `""` |  |
| global.rabbitmq.auth.tls.enabled | bool | `false` |  |
| global.rabbitmq.auth.username | string | `""` |  |
| global.rabbitmq.name | string | `"rabbitmq"` |  |
| global.rabbitmq.servicePort | int | `5672` |  |
| global.trentoWanda.name | string | `""` |  |
| global.trentoWanda.servicePort | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"ghcr.io/trento-project/trento-wanda"` |  |
| image.tag | string | `"2.1.0"` |  |
| imagePullSecrets | list | `[]` |  |
| ingress.annotations."kubernetes.io/tls-acme" | string | `"true"` |  |
| ingress.className | string | `"traefik"` |  |
| ingress.enabled | bool | `true` |  |
| ingress.hosts[0].host | string | `""` |  |
| ingress.hosts[0].paths[0].path | string | `"/wanda"` |  |
| ingress.hosts[0].paths[0].pathType | string | `"ImplementationSpecific"` |  |
| ingress.tls | list | `[]` |  |
| nameOverride | string | `""` |  |
| nodeSelector | object | `{}` |  |
| podAnnotations | object | `{}` |  |
| podSecurityContext | object | `{}` |  |
| postgresql.image.registry | string | `"registry.suse.com"` |  |
| postgresql.image.repository | string | `"suse/postgres"` |  |
| postgresql.image.tag | string | `"14"` |  |
| replicaCount | int | `1` |  |
| resources | object | `{}` |  |
| secretKeyBase | string | `""` |  |
| securityContext | object | `{}` |  |
| service.port | int | `4000` |  |
| service.type | string | `"ClusterIP"` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| tolerations | list | `[]` |  |

