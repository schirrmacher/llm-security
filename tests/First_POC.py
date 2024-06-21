import re
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
import time
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from llama_index.core import VectorStoreIndex, Document
from llama_index.llms.mistralai import MistralAI
from llama_index.embeddings.fastembed import FastEmbedEmbedding
from llama_index.core import Settings
from llama_index.core import download_loader

def fetch_page(url, driver):
    driver.get(url)
    time.sleep(5) 
    return driver.page_source

def extract_date(text):
    date_patterns = [
        (re.compile(r'(\d{4}-\d{2}-\d{2})'), "%Y-%m-%d"),
        (re.compile(r'(\d{4}/\d{2}/\d{2})'), "%Y/%m/%d")
    ]
    for pattern, date_format in date_patterns:
        match = pattern.search(text)
        if match:
            return datetime.strptime(match.group(1), date_format)
    return None

def extract_cve_ids(text):
    cve_pattern = re.compile(r'CVE-2024-\d{4,7}')
    return cve_pattern.findall(text)

def filter_documents_by_date_or_cve(documents, threshold_date):
    filtered_docs = []
    for doc in documents:
        date = extract_date(doc.text)
        cve_list = extract_cve_ids(doc.text)
        if (date and date >= threshold_date) or cve_list:
            filtered_docs.append(doc)
    return filtered_docs

def query(index, query_str, threshold_date):
    query_engine = index.as_query_engine()
    response = query_engine.query(query_str)
    relevant_docs = []

    print("Response:", response)

    if hasattr(response, 'nodes'):
        for node in response.nodes:
            date = extract_date(node.text)
            cve_list = extract_cve_ids(node.text)
            if (date and date >= threshold_date) or cve_list:
                summary = node.metadata.get("summary", "No summary available")
                text = node.text
                relevant_docs.append((summary, text))
    elif hasattr(response, 'documents'):
        for document in response.documents:
            date = extract_date(document.text)
            cve_list = extract_cve_ids(document.text)
            if (date and date >= threshold_date) or cve_list:
                summary = document.metadata.get("summary", "No summary available")
                text = document.text
                relevant_docs.append((summary, text))
    elif isinstance(response, list):
        for document in response:
            date = extract_date(document.text)
            cve_list = extract_cve_ids(document.text)
            if (date and date >= threshold_date) or cve_list:
                summary = document.metadata.get("summary", "No summary available")
                text = document.text
                relevant_docs.append((summary, text))
    
    return relevant_docs

def main():
    llm = MistralAI(model="mistral-large-latest")

    embed_model = FastEmbedEmbedding(model_name="BAAI/bge-small-en-v1.5")
    Settings.embed_model = embed_model
    Settings.chunk_size = 1024
    Settings.llm = llm

    load_dotenv()

    urls = [
        "https://www.cvedetails.com/vulnerability-list/vendor_id-33168/Opentelemetry.html",
        "https://www.cvedetails.com/vulnerability-list/vendor_id-14185/Golang.html",
        "https://www.cvedetails.com/vulnerability-list/vendor_id-15867/Kubernetes.html",
        "https://www.cvedetails.com/vulnerability-list/vendor_id-3080/product_id-25405/Fortinet-Forticlient.html"
    ]

    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    driver = webdriver.Chrome(options=options)

    selenium_documents = []
    for url in urls:
        try:
            page_source = fetch_page(url, driver)
            soup = BeautifulSoup(page_source, 'html.parser')
            text_content = soup.get_text(separator=' ', strip=True)
            selenium_documents.append(Document(text=text_content, metadata={'URL': url}))
            print(f"Fetched content from {url}")
        except Exception as e:
            print(f"Failed to fetch content from {url}: {str(e)}")

    driver.quit()

    BeautifulSoupWebReader = download_loader("BeautifulSoupWebReader")
    loader = BeautifulSoupWebReader()

    remaining_urls = [
        "https://cloud.google.com/support/bulletins",
        "https://openjdk.org/groups/vulnerability/advisories/",
        "https://spring.io/security",
        "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Kubernetes",
        "https://www.cloudvulndb.org/results?tags=GCP"
    ]

    soup_documents = loader.load_data(urls=remaining_urls)

    all_documents = selenium_documents + soup_documents

    for doc in all_documents:
        print(f"Document URL: {doc.metadata.get('URL', 'No URL')}")

    threshold_date = datetime.strptime("2024-01-01", "%Y-%m-%d")
    filtered_documents = filter_documents_by_date_or_cve(all_documents, threshold_date)

    index = VectorStoreIndex.from_documents(filtered_documents)

    technologies = ["Google Cloud Platform", "Kubernetes", "Golang", "OpenTelemetry","Forticlient"]
    for tech in technologies:
        print(f"\n{'='*20}\nQuerying for {tech}\n{'='*20}")
        query_str = f"Provide any recent security advisories or known issues for {tech} that have been published since {threshold_date.date()}? Specifically, we are looking for any new vulnerabilities, patches."        
        relevant_docs = query(index, query_str, threshold_date)
        for summary, text in relevant_docs:
            print(f"Summary: {summary}")
            print(f"Text: {text}\n")

if __name__ == "__main__":
    main()
