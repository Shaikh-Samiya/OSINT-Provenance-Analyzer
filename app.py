
import streamlit as st
import pandas as pd
import socket
import whois
import ipaddress
import dns.resolver
import requests
from urllib.parse import urlparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from email import policy
from email.parser import Parser
from datetime import datetime
from io import BytesIO

st.set_page_config(
    page_title="OSINT Provenance Analyzer",
    page_icon="🔎",
    layout="wide"
)

st.title("🔎 OSINT-Based Online Content Origin and Provenance Analyzer")
st.caption(
    "Investigate domain information, webpage history, "
    "image origins, and publicly accessible online content."
)

st.info(
    "Use this tool for authorized, ethical investigations. "
    "Results may be incomplete and should be independently verified."
)

if "findings" not in st.session_state:
    st.session_state.findings = []

def normalize_domain(value):
    value = value.strip()
    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)
    domain = parsed.hostname

    if not domain or "." not in domain:
        raise ValueError("Enter a valid domain, such as example.com.")

    if any(char.isspace() for char in domain):
        raise ValueError("The domain must not contain spaces.")

    return domain.lower()

tab1, tab2, tab3, tab4 = st.tabs([
    "🌐 Domain Investigation",
    "🕒 Webpage History",
    "🖼️ Image Investigation",
    "📊 Investigation Report"
])


with tab1:
    st.subheader("Domain and DNS Lookup")

    domain_input = st.text_input(
        "Enter a domain or website URL",
        placeholder="example.com",
        key="domain_investigation_input"
    )

    if st.button("Investigate Domain"):
        try:
            domain = normalize_domain(domain_input)

            st.write("### Domain")
            st.code(domain)

            # DNS record lookup
            st.write("### DNS Records")

            dns_results = {}

            for record_type in ["A", "AAAA", "MX", "NS"]:
                try:
                    answers = dns.resolver.resolve(
                        domain,
                        record_type,
                        lifetime=5
                    )

                    if record_type == "MX":
                        records = [
                            f"Priority: {answer.preference}, "
                            f"Mail server: {answer.exchange}"
                            for answer in answers
                        ]
                    else:
                        records = [str(answer) for answer in answers]

                    dns_results[record_type] = records

                except Exception:
                    dns_results[record_type] = [
                        "No record found or lookup unavailable"
                    ]

            st.json(dns_results)

            st.session_state.findings.append({
                "Time": datetime.now().isoformat(timespec="seconds"),
                "Type": "DNS Records",
                "Target": domain,
                "Finding": str(dns_results)
            })

            # Existing IPv4 lookup
            try:
                ip_address = socket.gethostbyname(domain)

                st.write("**Resolved IPv4 address:**", ip_address)

                st.session_state.findings.append({
                    "Time": datetime.now().isoformat(timespec="seconds"),
                    "Type": "DNS Lookup",
                    "Target": domain,
                    "Finding": f"Resolved IPv4 address: {ip_address}"
                })

            except socket.gaierror:
                st.warning(
                    "DNS lookup did not return an IPv4 address."
                )

            # WHOIS lookup
            with st.spinner("Requesting available WHOIS information..."):
                try:
                    result = whois.whois(domain)

                    details = {
                        "Domain Name": str(result.domain_name),
                        "Registrar": str(result.registrar),
                        "Creation Date": str(result.creation_date),
                        "Expiry Date": str(result.expiration_date),
                        "Updated Date": str(result.updated_date),
                        "Name Servers": str(result.name_servers),
                        "Status": str(result.status)
                    }

                    st.write("### WHOIS Information")
                    st.json(details)

                    st.session_state.findings.append({
                        "Time": datetime.now().isoformat(
                            timespec="seconds"
                        ),
                        "Type": "WHOIS Lookup",
                        "Target": domain,
                        "Finding": str(details)
                    })

                except Exception as error:
                    st.warning(
                        "WHOIS information could not be retrieved. "
                        "The server may limit requests or hide registration data."
                    )
                    st.caption(f"Technical detail: {error}")

        except ValueError as error:
            st.error(str(error))


with tab2:
    st.subheader("Explore Webpage History")

    history_url = st.text_input(
        "Enter the URL to investigate",
        placeholder="https://example.com/article"
    )

    if history_url.strip():
        parsed = urlparse(history_url.strip())

        if parsed.scheme in ("http", "https") and parsed.hostname:
            encoded_url = history_url.strip()
            wayback_url = (
                "https://web.archive.org/web/*/" + encoded_url
            )

            st.markdown(
                f"[Open Wayback Machine history]({wayback_url})"
            )
            st.caption(
                "The Wayback Machine opens in a new page. "
                "Its archived results are not automatically imported into this dashboard."
            )

            if st.button("Record History Investigation"):
                st.session_state.findings.append({
                    "Time": datetime.now().isoformat(timespec="seconds"),
                    "Type": "Webpage History",
                    "Target": encoded_url,
                    "Finding": f"Wayback Machine search: {wayback_url}"
                })
                st.success("Investigation link recorded.")
        else:
            st.caption("Enter a complete URL starting with http:// or https://.")

with tab3:
    st.subheader("Image Origin Investigation")

    image_url = st.text_input(
        "Optional: enter an image URL",
        placeholder="https://example.com/image.jpg"
    )

    if image_url.strip():
        st.markdown(
            f"[Open Google Lens](https://lens.google.com/)"
        )
        st.markdown(
            f"[Open TinEye Reverse Image Search](https://tineye.com/)"
        )
        st.caption(
            "These services may require you to upload the image or enter its URL. "
            "This dashboard does not automatically submit images to them."
        )

        if st.button("Record Image Investigation"):
            st.session_state.findings.append({
                "Time": datetime.now().isoformat(timespec="seconds"),
                "Type": "Image Investigation",
                "Target": image_url.strip(),
                "Finding": "Reverse-image search links provided for manual investigation."
            })
            st.success("Investigation recorded.")

    else:
        st.write("Enter an image URL to display investigation options.")

with tab4:
    st.subheader("Investigation Findings")

    if st.session_state.findings:
        findings_df = pd.DataFrame(st.session_state.findings)
        st.dataframe(findings_df, use_container_width=True)

        csv_data = findings_df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="Download Findings as CSV",
            data=csv_data,
            file_name="osint_investigation_report.csv",
            mime="text/csv"
        )

        if st.button("Clear Investigation Findings"):
            st.session_state.findings = []
            st.rerun()
    else:
        st.info("No findings recorded yet. Run an investigation first.")


# ---------------- Google Dorks and Cross-Referencing ----------------

st.divider()
st.header("🔎 Google Dorks and Cross-Referencing")
st.write(
    "Generate search queries to find publicly available information "
    "and compare information across sources."
)

dork_type = st.selectbox(
    "Choose an investigation type",
    [
        "Search for a specific phrase",
        "Find PDFs on a website",
        "Find publicly listed contact pages",
        "Find pages containing a keyword",
        "Cross-reference a news claim"
    ]
)

target = st.text_input(
    "Enter a website, keyword, or claim",
    placeholder="e.g., example.com or climate research"
)

if st.button("Generate Search Query"):
    if not target.strip():
        st.warning("Please enter a website, keyword, or claim.")
    else:
        value = target.strip()

        if dork_type == "Search for a specific phrase":
            query = f'"{value}"'

        elif dork_type == "Find PDFs on a website":
            domain = value.replace("https://", "").replace("http://", "").split("/")[0]
            query = f"site:{domain} filetype:pdf"

        elif dork_type == "Find publicly listed contact pages":
            domain = value.replace("https://", "").replace("http://", "").split("/")[0]
            query = f"site:{domain} (contact OR about)"

        elif dork_type == "Find pages containing a keyword":
            query = f'"{value}"'

        else:
            query = f'"{value}" (news OR report OR statement)'

        st.code(query, language="text")
        search_url = (
            "https://www.google.com/search?q="
            + requests.utils.quote(query)
        )

        st.link_button("Search Google", search_url)

        st.info(
            "Search results are leads for investigation, not proof. "
            "Cross-check dates, original sources, and independent reporting."
        )

# ---------------- Existing Footer ----------------


# ---------------- Website Technology Detection ----------------

st.divider()
st.header("🧩 Website Technology Detection")

st.write(
    "Inspect publicly accessible website headers and HTML for "
    "technology indicators. Results are clues, not guaranteed identification."
)

website_url = st.text_input(
    "Enter a website URL to inspect",
    placeholder="https://example.com",
    key="technology_website_url"
)

if st.button("Detect Website Technologies"):
    if not website_url.strip():
        st.warning("Please enter a website URL.")
    else:
        try:
            parsed_url = urlparse(website_url.strip())

            if (
                parsed_url.scheme not in ("http", "https")
                or not parsed_url.hostname
            ):
                st.error("Enter a complete URL starting with https:// or http://.")
            else:
                with st.spinner("Inspecting public website information..."):
                    response = requests.get(
                        website_url.strip(),
                        timeout=10,
                        headers={"User-Agent": "OSINT-Provenance-Analyzer/1.0"}
                    )

                st.write("### HTTP Response")
                st.write("**Status code:**", response.status_code)

                headers = response.headers

                st.write("### Server and Framework Indicators")

                indicators = {
                    "Server": headers.get("Server", "Not disclosed"),
                    "X-Powered-By": headers.get(
                        "X-Powered-By", "Not disclosed"
                    ),
                    "Content-Type": headers.get(
                        "Content-Type", "Not disclosed"
                    ),
                }

                st.json(indicators)

                soup = BeautifulSoup(response.text, "html.parser")

                technologies = []

                generator = soup.find("meta", attrs={"name": "generator"})
                if generator and generator.get("content"):
                    technologies.append(
                        "Generator metadata: " + generator["content"]
                    )

                if soup.find("meta", attrs={"name": "next-head-count"}):
                    technologies.append("Possible Next.js indicator")

                if soup.find(id="__next"):
                    technologies.append("Possible Next.js indicator")

                if soup.find(id="__nuxt"):
                    technologies.append("Possible Nuxt.js indicator")

                if soup.find("meta", attrs={"name": "wp-content"}):
                    technologies.append("Possible WordPress-related metadata")

                for script in soup.find_all("script", src=True):
                    src = script["src"].lower()

                    if "jquery" in src:
                        technologies.append("jQuery reference found")
                    if "react" in src:
                        technologies.append("React reference found")
                    if "vue" in src:
                        technologies.append("Vue.js reference found")

                technologies = list(dict.fromkeys(technologies))

                st.write("### Detected Technology Clues")

                if technologies:
                    for technology in technologies:
                        st.write("- ", technology)
                else:
                    st.info(
                        "No obvious technology indicators were found. "
                        "Technologies may be hidden or loaded dynamically."
                    )

                st.session_state.findings.append({
                    "Time": datetime.now().isoformat(timespec="seconds"),
                    "Type": "Website Technology Detection",
                    "Target": website_url.strip(),
                    "Finding": (
                        f"HTTP status: {response.status_code}; "
                        f"Indicators: {indicators}; "
                        f"Technology clues: {technologies}"
                    )
                })

                st.success("Technology inspection recorded in Investigation Report.")

        except requests.RequestException as error:
            st.error("Could not retrieve the website.")
            st.caption(f"Technical detail: {error}")

        except Exception as error:
            st.error("An unexpected error occurred during inspection.")
            st.caption(f"Technical detail: {error}")



# ---------------- Email Header Analysis ----------------

st.divider()
st.header("📧 Email Header Analysis")

st.write(
    "Paste the original email headers to inspect routing information, "
    "timestamps, sender-related fields, and authentication results. "
    "Remove personal information before sharing headers."
)

email_headers = st.text_area(
    "Paste email headers here",
    height=220,
    placeholder=(
        "From: sender@example.com\n"
        "To: recipient@example.com\n"
        "Subject: Example message\n"
        "Date: Sat, 17 Oct 2026 10:00:00 +0000\n"
        "Received: from mail.example.com ...\n"
        "Authentication-Results: ...\n"
    ),
    key="email_headers_input"
)

if st.button("Analyze Email Headers"):
    if not email_headers.strip():
        st.warning("Please paste email headers first.")
    else:
        try:
            message = Parser(policy=policy.default).parsestr(
                email_headers,
                headersonly=True
            )

            fields = [
                "From",
                "To",
                "Reply-To",
                "Return-Path",
                "Subject",
                "Date",
                "Message-ID",
                "Authentication-Results"
            ]

            st.subheader("Header Summary")

            summary = {}
            for field in fields:
                value = message.get(field)
                summary[field] = str(value) if value else "Not present"

            st.json(summary)

            received_headers = message.get_all("Received", [])
            st.subheader("Mail Routing Information")

            if received_headers:
                for index, received in enumerate(received_headers, start=1):
                    st.write(f"**Received header {index}:**")
                    st.code(str(received))
            else:
                st.info("No Received headers were provided.")

            auth_results = message.get_all(
                "Authentication-Results", []
            )

            st.subheader("Authentication Indicators")

            if auth_results:
                for result in auth_results:
                    st.write(str(result))
            else:
                st.info(
                    "No Authentication-Results header was provided. "
                    "This does not establish whether the email is genuine."
                )

            st.session_state.findings.append({
                "Time": datetime.now().isoformat(timespec="seconds"),
                "Type": "Email Header Analysis",
                "Target": str(message.get("From", "Sender not provided")),
                "Finding": (
                    f"Header summary: {summary}; "
                    f"Received headers: {len(received_headers)}"
                )
            })

            st.success("Email header findings recorded in the investigation report.")

        except Exception as error:
            st.error("Could not parse the supplied headers.")
            st.caption(f"Technical detail: {error}")



# ---------------- Website Crawling ----------------

st.divider()
st.header("🕸️ Website Crawling")

st.write(
    "Collect public internal links from a website to understand its URL "
    "structure. Only crawl websites you are authorized to investigate."
)

crawl_url = st.text_input(
    "Website URL to crawl",
    placeholder="https://example.com",
    key="crawl_url_input"
)

max_pages = st.number_input(
    "Maximum pages to visit",
    min_value=1,
    max_value=30,
    value=10,
    step=1,
    key="crawl_max_pages"
)

if st.button("Start Website Crawl"):
    if not crawl_url.strip():
        st.warning("Please enter a website URL.")
    else:
        try:
            parsed_url = urlparse(
                crawl_url.strip()
                if "://" in crawl_url
                else "https://" + crawl_url.strip()
            )

            if (
                parsed_url.scheme not in ("http", "https")
                or not parsed_url.hostname
                or "." not in parsed_url.hostname
                or any(char.isspace() for char in parsed_url.hostname)
                or parsed_url.username
                or parsed_url.password
            ):
                st.error("Enter a valid public website URL.")
            else:
                from collections import deque
                from bs4 import BeautifulSoup
                import ipaddress

                start_url = parsed_url.geturl()
                base_domain = parsed_url.hostname.lower()
                queue = deque([start_url])
                visited = set()
                discovered_links = set()
                crawl_results = []
                blocked_hosts = {
                    "localhost",
                    "localhost.localdomain",
                    "metadata.google.internal"
                }

                def is_public_host(hostname):
                    if not hostname:
                        return False

                    hostname = hostname.rstrip(".").lower()

                    if hostname in blocked_hosts or hostname.endswith(".local"):
                        return False

                    try:
                        addresses = socket.getaddrinfo(
                            hostname, None, type=socket.SOCK_STREAM
                        )

                        if not addresses:
                            return False

                        for address in addresses:
                            ip = ipaddress.ip_address(address[4][0])
                            if not ip.is_global:
                                return False

                        return True
                    except (OSError, ValueError):
                        return False

                if not is_public_host(base_domain):
                    st.error(
                        "The hostname could not be verified as a public "
                        "internet host. Check the URL and try again."
                    )
                else:
                    progress = st.progress(0)
                    status = st.empty()

                    while queue and len(visited) < int(max_pages):
                        current_url = queue.popleft()

                        if current_url in visited:
                            continue

                        visited.add(current_url)
                        status.write(
                            f"Visiting page {len(visited)}: {current_url}"
                        )

                        try:
                            response = requests.get(
                                current_url,
                                timeout=8,
                                headers={
                                    "User-Agent": "OSINT-Provenance-Analyzer/1.0"
                                },
                                allow_redirects=False
                            )

                            if response.is_redirect:
                                crawl_results.append({
                                    "URL": current_url,
                                    "Status": response.status_code,
                                    "Title": "Redirect not followed",
                                    "Internal Links": 0
                                })
                                progress.progress(
                                    min(len(visited) / int(max_pages), 1.0)
                                )
                                continue

                            content_type = response.headers.get(
                                "Content-Type", ""
                            ).lower()

                            if (
                                response.status_code != 200
                                or "text/html" not in content_type
                                or len(response.content) > 2_000_000
                            ):
                                crawl_results.append({
                                    "URL": current_url,
                                    "Status": response.status_code,
                                    "Title": "Not an HTML page or page too large",
                                    "Internal Links": 0
                                })
                                progress.progress(
                                    min(len(visited) / int(max_pages), 1.0)
                                )
                                continue

                            soup = BeautifulSoup(
                                response.text, "html.parser"
                            )

                            title_tag = soup.find("title")
                            page_title = (
                                title_tag.get_text(" ", strip=True)
                                if title_tag else "No title"
                            )

                            page_links = set()

                            for tag in soup.find_all("a", href=True):
                                absolute_url = urljoin(
                                    response.url, tag["href"].strip()
                                )
                                link_parts = urlparse(absolute_url)

                                if (
                                    link_parts.scheme not in ("http", "https")
                                    or not link_parts.hostname
                                    or link_parts.username
                                    or link_parts.password
                                ):
                                    continue

                                if (
                                    link_parts.hostname.lower() == base_domain
                                    and link_parts.port in (None, 80, 443)
                                ):
                                    clean_url = link_parts._replace(
                                        fragment=""
                                    ).geturl()

                                    if clean_url not in visited:
                                        page_links.add(clean_url)
                                        discovered_links.add(clean_url)

                            crawl_results.append({
                                "URL": current_url,
                                "Status": response.status_code,
                                "Title": page_title,
                                "Internal Links": len(page_links)
                            })

                            for link in sorted(page_links):
                                if (
                                    link not in visited
                                    and link not in queue
                                    and len(visited) + len(queue) < int(max_pages)
                                ):
                                    queue.append(link)

                        except requests.RequestException as error:
                            crawl_results.append({
                                "URL": current_url,
                                "Status": "Error",
                                "Title": str(error)[:150],
                                "Internal Links": 0
                            })

                        progress.progress(
                            min(len(visited) / int(max_pages), 1.0)
                        )

                    status.write("Crawl finished.")

                    if crawl_results:
                        crawl_df = pd.DataFrame(crawl_results)

                        st.subheader("Crawl Summary")
                        st.write(f"Pages visited: {len(visited)}")
                        st.write(
                            f"Unique internal links discovered: "
                            f"{len(discovered_links)}"
                        )
                        st.dataframe(crawl_df, use_container_width=True)

                        st.subheader("Discovered Internal URLs")
                        if discovered_links:
                            st.dataframe(
                                pd.DataFrame({
                                    "Internal URL": sorted(discovered_links)
                                }),
                                use_container_width=True
                            )
                        else:
                            st.info("No internal links were discovered.")

                        csv_data = crawl_df.to_csv(
                            index=False
                        ).encode("utf-8")

                        st.download_button(
                            "Download Crawl Results (CSV)",
                            data=csv_data,
                            file_name="website_crawl_results.csv",
                            mime="text/csv"
                        )

                        st.session_state.findings.append({
                            "Time": datetime.now().isoformat(
                                timespec="seconds"
                            ),
                            "Type": "Website Crawling",
                            "Target": start_url,
                            "Finding": (
                                f"Pages visited: {len(visited)}; "
                                f"unique internal links discovered: "
                                f"{len(discovered_links)}"
                            )
                        })

                        st.success(
                            "Crawl summary recorded in the investigation report."
                        )
                    else:
                        st.warning("No pages could be crawled.")

        except Exception as error:
            st.error("The website crawl could not be completed.")
            st.caption(f"Technical detail: {error}")


# ---------------- IP Address Geolocation ----------------

st.divider()
st.header("🌍 IP Address Geolocation")

st.write(
    "Look up public IP address information, including approximate "
    "location, organization, and network details."
)

ip_input = st.text_input(
    "Enter a public IPv4 or IPv6 address",
    placeholder="8.8.8.8",
    key="ip_geolocation_input"
)

if st.button("Look Up IP Address"):
    if not ip_input.strip():
        st.warning("Please enter an IP address.")
    else:
        try:
            ip_obj = ipaddress.ip_address(ip_input.strip())

            if not ip_obj.is_global:
                st.error(
                    "Please enter a globally routable public IP address."
                )
            else:
                with st.spinner("Looking up IP information..."):
                    response = requests.get(
                        f"https://ipwho.is/{ip_obj}",
                        timeout=10
                    )
                    response.raise_for_status()
                    ip_data = response.json()

                if not ip_data.get("success", False):
                    st.error(
                        "The geolocation service could not find information "
                        "for this IP address."
                    )
                    st.caption(
                        str(ip_data.get("message", "No further details"))
                    )
                else:
                    connection = ip_data.get("connection") or {}

                    results = {
                        "IP Address": ip_data.get("ip", "Not available"),
                        "Type": ip_data.get("type", "Not available"),
                        "Country": ip_data.get("country", "Not available"),
                        "Region": ip_data.get("region", "Not available"),
                        "City": ip_data.get("city", "Not available"),
                        "Postal Code": ip_data.get("postal", "Not available"),
                        "Latitude": ip_data.get("latitude", "Not available"),
                        "Longitude": ip_data.get("longitude", "Not available"),
                        "ISP": connection.get("isp", "Not available"),
                        "Organization": connection.get(
                            "org", "Not available"
                        ),
                        "Domain": connection.get(
                            "domain", "Not available"
                        ),
                        "Timezone": (
                            (ip_data.get("timezone") or {}).get(
                                "id", "Not available"
                            )
                        )
                    }

                    st.subheader("Geolocation Results")
                    st.dataframe(
                        pd.DataFrame(
                            results.items(),
                            columns=["Field", "Value"]
                        ),
                        use_container_width=True,
                        hide_index=True
                    )

                    latitude = ip_data.get("latitude")
                    longitude = ip_data.get("longitude")

                    if (
                        isinstance(latitude, (int, float))
                        and isinstance(longitude, (int, float))
                    ):
                        st.subheader("Approximate Location Map")
                        st.map(
                            pd.DataFrame({
                                "lat": [latitude],
                                "lon": [longitude]
                            })
                        )

                    st.session_state.findings.append({
                        "Time": datetime.now().isoformat(
                            timespec="seconds"
                        ),
                        "Type": "IP Geolocation",
                        "Target": str(ip_obj),
                        "Finding": (
                            f"Country: {results['Country']}; "
                            f"Region: {results['Region']}; "
                            f"City: {results['City']}; "
                            f"ISP: {results['ISP']}"
                        )
                    })

                    st.success(
                        "IP geolocation results added to the investigation report."
                    )

                    st.caption(
                        "Location information is approximate and may describe "
                        "the network provider's location rather than a person's "
                        "actual location. Results depend on the external service."
                    )

        except ValueError:
            st.error("Invalid IP address. Enter a valid IPv4 or IPv6 address.")
        except requests.RequestException as error:
            st.error("Could not contact the geolocation service.")
            st.caption(f"Technical detail: {error}")
        except Exception as error:
            st.error("An unexpected error occurred during the lookup.")
            st.caption(f"Technical detail: {error}")



# ---------------- Public Email Address Enumeration ----------------

st.divider()
st.header("📧 Public Email Address Enumeration")

st.write(
    "Generate search queries to investigate email addresses that may "
    "be publicly listed on a domain or website. Search results must be "
    "checked manually and may be incomplete."
)

email_domain = st.text_input(
    "Enter a domain to investigate",
    placeholder="example.com",
    key="email_enum_domain"
)

email_search_type = st.selectbox(
    "Choose a search method",
    [
        "Search for email addresses on a domain",
        "Search for a specific email address",
        "Search public contact pages",
        "Search public PDF documents"
    ],
    key="email_enum_type"
)

email_search_value = st.text_input(
    "Optional: enter an email address or keyword",
    placeholder="e.g., contact or user@example.com",
    key="email_enum_value"
)

if st.button("Generate Email Investigation Queries"):
    cleaned_domain = email_domain.strip().lower()

    if (
        not cleaned_domain
        or "." not in cleaned_domain
        or " " in cleaned_domain
        or "/" in cleaned_domain
        or "@" in cleaned_domain
    ):
        st.warning("Enter a domain such as example.com.")
    else:
        query_value = email_search_value.strip()

        if email_search_type == "Search for email addresses on a domain":
            queries = [
                f'site:{cleaned_domain} "@{cleaned_domain}"',
                f'site:{cleaned_domain} "email" OR "contact"',
                f'"@{cleaned_domain}"'
            ]

        elif email_search_type == "Search for a specific email address":
            if (
                not query_value
                or "@" not in query_value
                or query_value.startswith("@")
                or query_value.endswith("@")
            ):
                st.warning("Enter a complete email address to search for.")
                queries = []
            else:
                queries = [f'"{query_value}"']

        elif email_search_type == "Search public contact pages":
            queries = [
                f'site:{cleaned_domain} contact',
                f'site:{cleaned_domain} about',
                f'site:{cleaned_domain} "email us"'
            ]

        else:
            queries = [
                f'site:{cleaned_domain} filetype:pdf email',
                f'site:{cleaned_domain} filetype:pdf contact'
            ]

        if queries:
            st.subheader("Generated Search Queries")

            for index, query in enumerate(queries, start=1):
                st.write(f"**Query {index}**")
                st.code(query, language="text")

                search_url = (
                    "https://www.google.com/search?q="
                    + requests.utils.quote(query)
                )

                st.link_button(
                    f"Search Google — Query {index}",
                    search_url,
                    key=f"email_enum_search_{index}"
                )

            if st.button("Record Email Enumeration Investigation"):
                st.session_state.findings.append({
                    "Time": datetime.now().isoformat(
                        timespec="seconds"
                    ),
                    "Type": "Public Email Enumeration",
                    "Target": cleaned_domain,
                    "Finding": (
                        f"Generated {len(queries)} public search queries "
                        f"using method: {email_search_type}. "
                        "Search results require manual verification."
                    )
                })

                st.success(
                    "Email enumeration investigation recorded in the report."
                )

            st.info(
                "This feature generates search queries only. It does not "
                "automatically collect, verify, or confirm email addresses. "
                "Use it for authorized research and respect privacy."
            )



# ---------------- News Verification and Fake News Analysis ----------------

st.divider()
st.header("📰 News Verification & Fake News Analysis")

st.write(
    "Investigate a news headline or claim by generating search queries "
    "and recording evidence from sources you review manually."
)

news_claim = st.text_area(
    "Enter the news headline or claim",
    placeholder="Example: A news report claims that a new policy was announced.",
    height=100,
    key="news_verification_claim"
)

news_topic = st.text_input(
    "Optional: publisher, website, or related keyword",
    placeholder="e.g., official government website",
    key="news_verification_topic"
)

if st.button("Generate News Verification Queries"):
    if not news_claim.strip():
        st.warning("Please enter a news headline or claim.")
    else:
        claim = news_claim.strip()
        topic = news_topic.strip()

        queries = [
            f'"{claim}"',
            f'"{claim}" (news OR report OR statement)',
            f'"{claim}" (fact check OR verification)',
            f'"{claim}" (official OR announcement)'
        ]

        if topic:
            queries.append(f'"{claim}" "{topic}"')

        st.subheader("Search Queries")

        for index, query in enumerate(queries, start=1):
            st.write(f"**Query {index}**")
            st.code(query, language="text")

            search_url = (
                "https://www.google.com/search?q="
                + requests.utils.quote(query)
            )

            st.link_button(
                f"Search Google — Query {index}",
                search_url,
                key=f"news_search_{index}"
            )

        st.info(
            "Search results are leads, not proof. Check original sources, "
            "publication dates, independent reporting, and whether the "
            "evidence directly supports the claim."
        )

        st.session_state["news_claim_for_review"] = claim
        st.session_state["news_topic_for_review"] = topic

st.subheader("Record Your Verification Assessment")

assessment_claim = st.session_state.get(
    "news_claim_for_review", ""
)

if not assessment_claim:
    assessment_claim = news_claim.strip()

assessment_status = st.selectbox(
    "Assessment status",
    [
        "Not yet assessed",
        "Supported by evidence",
        "Contradicted by evidence",
        "Partly supported / missing context",
        "Inconclusive"
    ],
    key="news_assessment_status"
)

supporting_evidence = st.text_area(
    "Supporting evidence and source URLs",
    placeholder="Describe evidence that supports the claim and list source URLs.",
    key="news_supporting_evidence"
)

contradicting_evidence = st.text_area(
    "Contradicting evidence and source URLs",
    placeholder="Describe conflicting evidence and list source URLs.",
    key="news_contradicting_evidence"
)

verification_notes = st.text_area(
    "Verification notes",
    placeholder="Record dates, source credibility, original statements, and limitations.",
    key="news_verification_notes"
)

if st.button("Save News Verification Assessment"):
    if not assessment_claim:
        st.warning("Enter a claim before saving an assessment.")
    else:
        evidence_summary = (
            f"Claim: {assessment_claim}\n"
            f"Assessment: {assessment_status}\n"
            f"Supporting evidence: {supporting_evidence.strip() or 'Not provided'}\n"
            f"Contradicting evidence: {contradicting_evidence.strip() or 'Not provided'}\n"
            f"Notes: {verification_notes.strip() or 'Not provided'}"
        )

        st.session_state.findings.append({
            "Time": datetime.now().isoformat(timespec="seconds"),
            "Type": "News Verification",
            "Target": assessment_claim,
            "Finding": evidence_summary
        })

        st.success("News verification assessment saved to your investigation report.")



st.divider()
st.caption(
    "OSINT research tool | Public information only | "
    "Verify findings before drawing conclusions."
)
