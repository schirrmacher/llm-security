import unittest
from unittest.mock import patch, mock_open
import json
from security_army_knife.trivy_importer import TrivyImporter
from security_army_knife.cve import CVE


class TestTrivyImporter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Sample JSON data based on the provided JSON
        cls.sample_json = {
            "SchemaVersion": 2,
            "ArtifactName": "europe-west1-docker.pkg.dev/pt-cicd/docker-snapshots/giftcards-service:main",
            "ArtifactType": "container_image",
            "Metadata": {
                "OS": {"Family": "debian", "Name": "11.8"},
                "ImageID": "sha256:d1cedc3dc1895042e624f3455bcd92b1895e0391111d7867acb0fee8882095eb",
                "DiffIDs": [
                    "sha256:54ad2ec71039b74f7e82f020a92a8c2ca45f16a51930d539b56973a18b8ffe8d",
                    # Other diff IDs...
                ],
                "RepoTags": [
                    "europe-west1-docker.pkg.dev/pt-cicd/docker-snapshots/giftcards-service:main"
                ],
                "RepoDigests": [
                    "europe-west1-docker.pkg.dev/pt-cicd/docker-snapshots/giftcards-service@sha256:62253536fbe895a90eb54e28800707d9087e7dbdf0fda71eb253b35141da57aa"
                ],
                "ImageConfig": {
                    "architecture": "amd64",
                    "created": "1970-01-01T00:00:00Z",
                    "history": [
                        # History entries...
                    ],
                    "os": "linux",
                    "rootfs": {
                        "type": "layers",
                        "diff_ids": [
                            "sha256:54ad2ec71039b74f7e82f020a92a8c2ca45f16a51930d539b56973a18b8ffe8d",
                            # Other diff IDs...
                        ],
                    },
                    "config": {
                        "Entrypoint": [
                            "java",
                            "-XX:InitialRAMPercentage=80.0",
                            "-XX:MaxRAMPercentage=80.0",
                            "-javaagent:/app/agent/opentelemetry-javaagent.jar",
                            "-Dio.opentelemetry.javaagent.slf4j.simpleLogger.logFile=System.out",
                            "-cp",
                            "@/app/jib-classpath-file",
                            "com.paymenttools.giftcards.GiftcardsServiceApplicationKt",
                        ],
                        "Env": [
                            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                            "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
                            "JAVA_VERSION=17.0.9",
                            "LANG=C.UTF-8",
                        ],
                        "Labels": {
                            "org.opencontainers.image.base.name": "unknown",
                            "org.opencontainers.image.created": "2024-01-02T13:51:28+0000",
                            "org.opencontainers.image.revision": "4d3760c8c421aa30d5b9a7c2bf5d63312c38e426",
                            "org.opencontainers.image.source": "https://github.com/paymenttools/giftcards-service",
                        },
                        "User": "0",
                        "WorkingDir": "/",
                        "ExposedPorts": {"8080/tcp": {}, "8081/tcp": {}},
                    },
                },
            },
            "Results": [
                {
                    "Target": "europe-west1-docker.pkg.dev/pt-cicd/docker-snapshots/giftcards-service:main (debian 11.8)",
                    "Class": "os-pkgs",
                    "Type": "debian",
                },
                {
                    "Target": "Java",
                    "Class": "lang-pkgs",
                    "Type": "jar",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-6378",
                            "PkgName": "ch.qos.logback:logback-classic",
                            "PkgPath": "app/libs/logback-classic-1.4.11.jar",
                            "InstalledVersion": "1.4.11",
                            "FixedVersion": "1.3.12, 1.4.12, 1.2.13",
                            "Layer": {
                                "Digest": "sha256:8cc2564f252de554d0d19116b7ac04436b8d5eff99db660860dc69b32f46dc9b",
                                "DiffID": "sha256:53db277baa15fb02afbbbce47fd3df05abe41602707d17058cd53ddd0d3a2809",
                            },
                            "SeveritySource": "ghsa",
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-6378",
                            "DataSource": {
                                "ID": "ghsa",
                                "Name": "GitHub Security Advisory Maven",
                                "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
                            },
                            "Title": "logback: serialization vulnerability in logback receiver",
                            "Description": "A serialization vulnerability in logback receiver component part of \nlogback version 1.4.11 allows an attacker to mount a Denial-Of-Service \nattack by sending poisoned data.\n\n",
                            "Severity": "HIGH",
                            "CweIDs": ["CWE-502"],
                            "CVSS": {
                                "ghsa": {
                                    "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
                                    "V3Score": 7.1,
                                },
                                "nvd": {
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                    "V3Score": 7.5,
                                },
                                "redhat": {
                                    "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
                                    "V3Score": 7.1,
                                },
                            },
                            "References": [
                                "https://access.redhat.com/security/cve/CVE-2023-6378",
                                "https://github.com/qos-ch/logback",
                                "https://github.com/qos-ch/logback/commit/9c782b45be4abdafb7e17481e24e7354c2acd1eb",
                                "https://github.com/qos-ch/logback/commit/b8eac23a9de9e05fb6d51160b3f46acd91af9731",
                                "https://github.com/qos-ch/logback/commit/bb095154be011267b64e37a1d401546e7cc2b7c3",
                                "https://github.com/qos-ch/logback/issues/745#issuecomment-1836227158",
                                "https://logback.qos.ch/manual/receivers.html",
                                "https://logback.qos.ch/news.html#1.2.13",
                                "https://logback.qos.ch/news.html#1.3.12",
                                "https://nvd.nist.gov/vuln/detail/CVE-2023-6378",
                                "https://www.cve.org/CVERecord?id=CVE-2023-6378",
                            ],
                            "PublishedDate": "2023-11-29T12:15:07.543Z",
                            "LastModifiedDate": "2023-12-05T21:00:10.557Z",
                        },
                        {
                            "VulnerabilityID": "CVE-2023-44487",
                            "PkgName": "io.netty:netty-codec-http2",
                            "PkgPath": "app/libs/netty-codec-http2-4.1.97.Final.jar",
                            "InstalledVersion": "4.1.97.Final",
                            "FixedVersion": "4.1.100.Final",
                            "Layer": {
                                "Digest": "sha256:8cc2564f252de554d0d19116b7ac04436b8d5eff99db660860dc69b32f46dc9b",
                                "DiffID": "sha256:53db277baa15fb02afbbbce47fd3df05abe41602707d17058cd53ddd0d3a2809",
                            },
                            "SeveritySource": "ghsa",
                            "PrimaryURL": "https://github.com/advisories/GHSA-xpw8-rcwv-8f8p",
                            "DataSource": {
                                "ID": "ghsa",
                                "Name": "GitHub Security Advisory Maven",
                                "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
                            },
                            "Title": "io.netty:netty-codec-http2 vulnerable to HTTP/2 Rapid Reset Attack",
                            "Description": "A client might overload the server by issue frequent RST frames. This can cause a massive amount of load on the remote system and so cause a DDOS attack. \n\n### Impact\nThis is a DDOS attack, any http2 server is affected and so you should update as soon as possible.\n\n### Patches\nThis is patched in version 4.1.100.Final.\n\n### Workarounds\nA user can limit the amount of RST frames that are accepted per connection over a timeframe manually using either an own `Http2FrameListener` implementation or an `ChannelInboundHandler` implementation (depending which http2 API is used).\n\n### References\n- https://www.cve.org/CVERecord?id=CVE-2023-44487\n- https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/\n- https://cloud.google.com/blog/products/identity-security/google-cloud-mitigated-largest-ddos-attack-peaking-above-398-million-rps/",
                            "Severity": "HIGH",
                            "CVSS": {
                                "ghsa": {
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                    "V3Score": 7.5,
                                }
                            },
                            "References": [
                                "https://github.com/apple/swift-nio-http2/security/advisories/GHSA-qppj-fm5r-hxr3",
                                "https://github.com/netty/netty",
                                "https://github.com/netty/netty/commit/58f75f665aa81a8cbcf6ffa74820042a285c5e61",
                                "https://github.com/netty/netty/security/advisories/GHSA-xpw8-rcwv-8f8p",
                                "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
                                "https://www.cve.org/CVERecord?id=CVE-2023-44487",
                            ],
                        },
                        {
                            "VulnerabilityID": "CVE-2023-34054",
                            "PkgName": "io.projectreactor.netty:reactor-netty-http",
                            "PkgPath": "app/libs/reactor-netty-http-1.1.10.jar",
                            "InstalledVersion": "1.1.10",
                            "FixedVersion": "1.1.13, 1.0.39",
                            "Layer": {
                                "Digest": "sha256:8cc2564f252de554d0d19116b7ac04436b8d5eff99db660860dc69b32f46dc9b",
                                "DiffID": "sha256:53db277baa15fb02afbbbce47fd3df05abe41602707d17058cd53ddd0d3a2809",
                            },
                            "SeveritySource": "ghsa",
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-34054",
                            "DataSource": {
                                "ID": "ghsa",
                                "Name": "GitHub Security Advisory Maven",
                                "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
                            },
                            "Title": "Reactor Netty HTTP Server denial of service vulnerability",
                            "Description": "\nIn Reactor Netty HTTP Server, versions 1.1.x prior to 1.1.13 and versions 1.0.x prior to 1.0.39, it is possible for a user to provide specially crafted HTTP requests that may cause a denial-of-service (DoS) condition.\n\nSpecifically, an application is vulnerable if Reactor Netty HTTP Server built-in integration with Micrometer is enabled.\n\n\n\n\n",
                            "Severity": "HIGH",
                            "CVSS": {
                                "ghsa": {
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                    "V3Score": 7.5,
                                },
                                "nvd": {
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                    "V3Score": 7.5,
                                },
                            },
                            "References": [
                                "https://github.com/reactor/reactor-netty",
                                "https://github.com/reactor/reactor-netty/releases/tag/v1.0.39",
                                "https://github.com/reactor/reactor-netty/releases/tag/v1.1.13",
                                "https://nvd.nist.gov/vuln/detail/CVE-2023-34054",
                                "https://spring.io/security/cve-2023-34054",
                            ],
                            "PublishedDate": "2023-11-28T09:15:07.147Z",
                            "LastModifiedDate": "2023-12-04T19:59:30.713Z",
                        },
                        {
                            "VulnerabilityID": "CVE-2022-1471",
                            "PkgName": "org.yaml:snakeyaml",
                            "PkgPath": "app/libs/snakeyaml-1.33.jar",
                            "InstalledVersion": "1.33",
                            "FixedVersion": "2.0",
                            "Layer": {
                                "Digest": "sha256:8cc2564f252de554d0d19116b7ac04436b8d5eff99db660860dc69b32f46dc9b",
                                "DiffID": "sha256:53db277baa15fb02afbbbce47fd3df05abe41602707d17058cd53ddd0d3a2809",
                            },
                            "SeveritySource": "ghsa",
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-1471",
                            "DataSource": {
                                "ID": "ghsa",
                                "Name": "GitHub Security Advisory Maven",
                                "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
                            },
                            "Title": "SnakeYaml: Constructor Deserialization Remote Code Execution",
                            "Description": "SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.\n",
                            "Severity": "HIGH",
                            "CweIDs": ["CWE-502", "CWE-20"],
                            "CVSS": {
                                "ghsa": {
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
                                    "V3Score": 8.3,
                                },
                                "nvd": {
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "V3Score": 9.8,
                                },
                                "redhat": {
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "V3Score": 9.8,
                                },
                            },
                            "References": [
                                "http://packetstormsecurity.com/files/175095/PyTorch-Model-Server-Registration-Deserialization-Remote-Code-Execution.html",
                                "http://www.openwall.com/lists/oss-security/2023/11/19/1",
                                "https://access.redhat.com/errata/RHSA-2022:9058",
                                "https://access.redhat.com/security/cve/CVE-2022-1471",
                                "https://bitbucket.org/snakeyaml/snakeyaml",
                                "https://bitbucket.org/snakeyaml/snakeyaml/commits/5014df1a36f50aca54405bb8433bc99a8847f758",
                                "https://bitbucket.org/snakeyaml/snakeyaml/commits/acc44099f5f4af26ff86b4e4e4cc1c874e2dc5c4",
                                "https://bitbucket.org/snakeyaml/snakeyaml/issues/561/cve-2022-1471-vulnerability-in#comment-64581479",
                                "https://bitbucket.org/snakeyaml/snakeyaml/issues/561/cve-2022-1471-vulnerability-in#comment-64634374",
                                "https://bitbucket.org/snakeyaml/snakeyaml/issues/561/cve-2022-1471-vulnerability-in#comment-64876314",
                                "https://bitbucket.org/snakeyaml/snakeyaml/wiki/CVE-2022-1471",
                                "https://bugzilla.redhat.com/2150009",
                                "https://bugzilla.redhat.com/show_bug.cgi?id=2150009",
                                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1471",
                                "https://errata.almalinux.org/8/ALSA-2022-9058.html",
                                "https://errata.rockylinux.org/RLSA-2022:9058",
                                "https://github.com/google/security-research/security/advisories/GHSA-mjmj-j48q-9wg2",
                                "https://github.com/mbechler/marshalsec",
                                "https://groups.google.com/g/kubernetes-security-announce/c/mwrakFaEdnc",
                                "https://linux.oracle.com/cve/CVE-2022-1471.html",
                                "https://linux.oracle.com/errata/ELSA-2022-9058-1.html",
                                "https://nvd.nist.gov/vuln/detail/CVE-2022-1471",
                                "https://security.netapp.com/advisory/ntap-20230818-0015/",
                                "https://snyk.io/blog/unsafe-deserialization-snakeyaml-java-cve-2022-1471/",
                                "https://www.cve.org/CVERecord?id=CVE-2022-1471",
                                "https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf?raw=true",
                            ],
                            "PublishedDate": "2022-12-01T11:15:10.553Z",
                            "LastModifiedDate": "2023-11-19T15:15:20.877Z",
                        },
                    ],
                },
            ],
        }

    @patch("builtins.open", new_callable=mock_open)
    def test_get_cve_objects(self, mock_file):
        mock_file.return_value.read.return_value = json.dumps(self.sample_json)

        trivy_importer = TrivyImporter("dummy_path.json")
        cve_objects = trivy_importer.get_cves()

        expected_cve_objects = [
            CVE(
                name="CVE-2023-6378",
                description="A serialization vulnerability in logback receiver component part of \nlogback version 1.4.11 allows an attacker to mount a Denial-Of-Service \nattack by sending poisoned data.\n\n",
            ),
            CVE(
                name="CVE-2023-44487",
                description="A client might overload the server by issue frequent RST frames. This can cause a massive amount of load on the remote system and so cause a DDOS attack. \n\n### Impact\nThis is a DDOS attack, any http2 server is affected and so you should update as soon as possible.\n\n### Patches\nThis is patched in version 4.1.100.Final.\n\n### Workarounds\nA user can limit the amount of RST frames that are accepted per connection over a timeframe manually using either an own `Http2FrameListener` implementation or an `ChannelInboundHandler` implementation (depending which http2 API is used).\n\n### References\n- https://www.cve.org/CVERecord?id=CVE-2023-44487\n- https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/\n- https://cloud.google.com/blog/products/identity-security/google-cloud-mitigated-largest-ddos-attack-peaking-above-398-million-rps/",
            ),
            CVE(
                name="CVE-2023-34054",
                description="\nIn Reactor Netty HTTP Server, versions 1.1.x prior to 1.1.13 and versions 1.0.x prior to 1.0.39, it is possible for a user to provide specially crafted HTTP requests that may cause a denial-of-service (DoS) condition.\n\nSpecifically, an application is vulnerable if Reactor Netty HTTP Server built-in integration with Micrometer is enabled.\n\n\n\n\n",
            ),
            CVE(
                name="CVE-2022-1471",
                description="SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.\n",
            ),
        ]

        for actual, expected in zip(cve_objects, expected_cve_objects):
            if actual != expected:
                self.assertEqual(str(actual), str(expected))


if __name__ == "__main__":
    unittest.main()
